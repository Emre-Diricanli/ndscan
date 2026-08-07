// Package engine owns the scan pipeline that the CLI, TUI, and web interface
// all run.
//
// Before this package existed the sequence — discover, merge the ARP cache,
// build the MAC map, scan ports, enrich hostnames, decide what to persist —
// was written out three times, once per front end. The copies drifted, and the
// drift was not cosmetic: cancelling a web scan corrupted change detection
// because only the TUI had learned not to save an interrupted run, and the two
// kept separate history baselines because they disagreed about the scan key.
//
// The deeper cause was that a finished scan was represented as []ui.Row, which
// cannot say how the run ended. A row slice looks identical whether the scan
// completed, was cancelled halfway, or lost half its hosts to errors — so every
// front end had to reconstruct that fact for itself, and they reconstructed it
// differently. Outcome makes it explicit and unavoidable.
package engine

import (
	"context"
	"sync"
	"time"

	"github.com/Emre-Diricanli/ndscan/internal/alert"
	"github.com/Emre-Diricanli/ndscan/internal/config"
	"github.com/Emre-Diricanli/ndscan/internal/scan"
	"github.com/Emre-Diricanli/ndscan/internal/ui"
)

// Plan is everything needed to run one scan. It is the front ends' only input
// to the pipeline: whatever a front end wants the scan to do, it says here.
type Plan struct {
	// SSHTarget runs the scan on another machine via SSH. Empty means local.
	SSHTarget string
	Targets   []string
	Preset    string
	// Ports is a port specification the scanner will parse ("22,80" or
	// "1-1024"). Empty means "let the preset choose".
	Ports string
	// HistoryPorts overrides how Ports appears in the history key. A front end
	// that selects ports indirectly — the web picks them via the preset alone —
	// needs the key to distinguish those selections even though the scan itself
	// passes no port spec. It must never be fed to the scanner: it is a label,
	// not a port list.
	HistoryPorts string

	ShowMAC     bool
	ShowVendors bool
	RootScan    bool // -sS, needs root on whichever machine runs nmap
	Concurrency int
	HostTimeout time.Duration

	// Fast prefers the native ARP+TCP sweep over nmap where it is viable. It is
	// a preference, not a guarantee: Outcome.Fast reports what actually ran.
	Fast bool
	// DiscoverOnly stops after finding live hosts, skipping the port scan.
	DiscoverOnly bool
	// Hostnames runs reverse-DNS enrichment once the rows are built.
	Hostnames bool
	// Multicast additionally asks the network what it calls itself, via mDNS
	// and SSDP. It finds names PTR cannot — most LANs have no reverse zone —
	// and it is the only pass that learns anything about devices which never
	// answer a TCP probe. Bounded by its own timeouts.
	Multicast bool
}

// Status describes how a run ended. It exists so that "we looked and found
// nothing" and "we never finished looking" stop being the same value.
type Status int

const (
	// StatusComplete: the scan probed everything it was asked to.
	StatusComplete Status = iota
	// StatusPartial: the scan finished, but some hosts errored or some probes
	// were skipped. The results are a floor, not the full picture.
	StatusPartial
	// StatusCancelled: the context was cancelled before the scan finished.
	StatusCancelled
	// StatusFailed: the scan could not run at all.
	StatusFailed
)

func (s Status) String() string {
	switch s {
	case StatusComplete:
		return "complete"
	case StatusPartial:
		return "partial"
	case StatusCancelled:
		return "cancelled"
	case StatusFailed:
		return "failed"
	}
	return "unknown"
}

// Timings records how long each phase took, for the TUI's timing line.
type Timings struct {
	Discovery  time.Duration
	Enrichment time.Duration
	Ports      time.Duration
	Total      time.Duration
}

// Outcome is the terminal result of a run: the rows, plus every fact a front
// end needs in order to describe the run honestly.
type Outcome struct {
	Status Status
	Rows   []ui.Row

	// Failed counts hosts whose scan returned an error. FirstErr is the first
	// such error, for a front end that wants to show one example rather than a
	// count alone.
	Failed   int
	FirstErr error
	// Fallbacks counts hosts where a requested SYN scan was retried as a TCP
	// connect, which is a quieter result than the user asked for.
	Fallbacks int

	// Fast reports whether the native sweep actually ran, which is not always
	// what Plan.Fast asked for — it is unavailable over SSH, for one. It
	// belongs in the history key, since a native sweep and an nmap scan
	// legitimately find different hosts.
	Fast bool
	// MACs maps IP to hardware address for every host we learned one for.
	MACs map[string]string

	Timings Timings
	// Err is set when Status is StatusFailed.
	Err error
}

// Comparable reports whether this run is trustworthy enough to become the
// baseline that later scans are compared against.
//
// A run that was cancelled, lost hosts, or found nothing at all is
// indistinguishable from a network where everything vanished. Saving it makes
// the next scan report the whole network as new, so one interruption corrupts
// change detection twice over.
func (o Outcome) Comparable() bool {
	return o.Status == StatusComplete && config.SaveEligible(false, o.Failed, len(o.Rows))
}

// ScanKey is the signature this run should be filed under in scan history.
func (o Outcome) ScanKey(p Plan) config.ScanKey {
	ports := p.Ports
	if p.HistoryPorts != "" {
		ports = p.HistoryPorts
	}
	return config.ScanKey{
		Targets: p.Targets,
		Ports:   ports,
		Preset:  p.Preset,
		Fast:    o.Fast,
	}
}

// Snapshots renders the run's rows as the minimal per-host state history keeps.
func (o Outcome) Snapshots() []config.HostSnapshot {
	out := make([]config.HostSnapshot, 0, len(o.Rows))
	for _, r := range o.Rows {
		out = append(out, config.HostSnapshot{IP: r.IP, Host: r.Host, Up: r.Up, Ports: r.Ports})
	}
	return out
}

// ----- events -----

// Phase names the stage a run is in. Front ends use it to label progress.
type Phase string

const (
	PhaseDiscover Phase = "discover"
	PhaseMAC      Phase = "mac"
	PhaseScan     Phase = "scan"
	PhaseEnrich   Phase = "enrich"
)

// Event is a progress notification emitted while a scan runs.
//
// One event type rather than several keeps the front-end adapters to a single
// switch, and keeps the engine from needing to know which of them cares about
// what. A front end that only wants the final answer can ignore events
// entirely — Run returns the Outcome regardless.
type Event struct {
	Kind EventKind

	// Phase, Done, Total describe progress. Total is 0 when unknown.
	Phase Phase
	Done  int
	Total int

	// Rows carries hosts for streaming front ends. What a consumer should do
	// with them depends on Kind: EventRows means these hosts are new and should
	// be appended, EventRowsUpdated means these are hosts already delivered
	// whose contents changed and should replace their existing entries.
	Rows []ui.Row

	// Native reports, on a PhaseScan event, whether the port scan is running
	// natively rather than through nmap. A front end that words its progress
	// differently for the two needs to know which is running, and recomputing
	// that decision outside the engine would mean two copies of it that drift.
	Native bool

	// Warning is a non-fatal problem worth telling the user about.
	Warning string
}

// EventKind distinguishes what an Event is reporting.
type EventKind int

const (
	// EventPhase reports entering a phase, or progress within it.
	EventPhase EventKind = iota
	// EventRows carries newly-scanned hosts as they complete. A consumer that
	// accumulates rows should append these.
	EventRows
	// EventRowsUpdated carries hosts that were already delivered via EventRows
	// and have since been revised — hostname enrichment fills a column on rows
	// the front end is already showing.
	//
	// This is a separate kind because the two cannot be told apart from the
	// payload alone, and treating an update as an arrival duplicates every row
	// on screen. A front end keyed by IP may handle both identically; one that
	// appends must not.
	EventRowsUpdated
	// EventWarning reports a non-fatal problem.
	EventWarning
)

// Emit receives events during a run. It is called from the scan's worker
// goroutines, so an implementation must be safe for concurrent use and must not
// block: the native sweep fans out across thousands of goroutines, and a slow
// consumer would stall the scan itself. Adapters that write to a channel should
// use a non-blocking send.
//
// A nil Emit is valid and means the caller only wants the Outcome.
type Emit func(Event)

func (e Emit) phase(p Phase, done, total int) {
	if e != nil {
		e(Event{Kind: EventPhase, Phase: p, Done: done, Total: total})
	}
}

// scanPhase reports port-scan progress along with which engine is doing it.
func (e Emit) scanPhase(done, total int, native bool) {
	if e != nil {
		e(Event{Kind: EventPhase, Phase: PhaseScan, Done: done, Total: total, Native: native})
	}
}

func (e Emit) rows(rows []ui.Row) {
	if e != nil && len(rows) > 0 {
		e(Event{Kind: EventRows, Rows: rows})
	}
}

func (e Emit) rowsUpdated(rows []ui.Row) {
	if e != nil && len(rows) > 0 {
		e(Event{Kind: EventRowsUpdated, Rows: rows})
	}
}

func (e Emit) warn(msg string) {
	if e != nil && msg != "" {
		e(Event{Kind: EventWarning, Warning: msg})
	}
}

// Runner builds the command runner for a plan. It is a field on Engine so tests
// can substitute a scripted runner without reaching the network.
type Engine struct {
	// NewRunner returns the runner for a plan. Defaults to scan.NewRunner,
	// which picks SSH or local based on Plan.SSHTarget.
	NewRunner func(sshTarget string) scan.Runner

	// Now supplies the current time. Tests substitute it to exercise cache
	// expiry without sleeping.
	Now func() time.Time

	// Cached multicast names, guarded because watch mode and a manual scan can
	// both be in enrichment at once.
	mcMu    sync.Mutex
	mcNames map[string]string
	mcAt    time.Time

	// The alert suppressor is held per-Engine so a long-lived watch loop stops
	// repeating itself, while each CLI invocation starts clean.
	alertMu  sync.Mutex
	alertSup *alert.Suppressor
}

// alertCooldown is how long the same rule may not fire twice for the same
// subject. Watch mode runs on the order of a minute, so this is chosen to be
// long enough that a persistent condition is reported once per sitting rather
// than once per interval.
const alertCooldown = time.Hour

// multicastTTL is how long a multicast discovery pass is reused. Device names
// change on the order of days; a minute of staleness is invisible next to the
// seconds each pass costs.
const multicastTTL = 5 * time.Minute

func (e *Engine) now() time.Time {
	if e.Now != nil {
		return e.Now()
	}
	return time.Now()
}

// New returns an Engine wired to the real scanner.
func New() *Engine {
	return &Engine{NewRunner: scan.NewRunner}
}

func (e *Engine) runnerFor(p Plan) scan.Runner {
	if e.NewRunner != nil {
		return e.NewRunner(p.SSHTarget)
	}
	return scan.NewRunner(p.SSHTarget)
}

// Run executes the plan and returns how it went.
//
// It never returns a nil Outcome: a run that failed outright still reports
// StatusFailed with the error attached, because a front end must be able to
// describe every ending, not just the good ones.
func (e *Engine) Run(ctx context.Context, p Plan, emit Emit) Outcome {
	start := time.Now()
	out := Outcome{MACs: map[string]string{}}
	runner := e.runnerFor(p)

	live, macs, rtts, fast, t, err := e.discover(ctx, p, runner, emit)
	out.Fast = fast
	out.Timings = t
	if err != nil {
		if ctx.Err() != nil {
			out.Status = StatusCancelled
			out.Timings.Total = time.Since(start)
			return out
		}
		out.Status = StatusFailed
		out.Err = err
		out.Timings.Total = time.Since(start)
		return out
	}
	if ctx.Err() != nil {
		out.Status = StatusCancelled
		out.Timings.Total = time.Since(start)
		return out
	}
	out.MACs = macs

	// No live hosts is a legitimate, complete answer — the caller decides
	// whether an empty network is plausible. It is not an error.
	if len(live) == 0 {
		out.Status = StatusComplete
		out.Timings.Total = time.Since(start)
		return out
	}

	e.scanPorts(ctx, p, runner, live, macs, rtts, emit, &out)

	if ctx.Err() != nil {
		out.Status = StatusCancelled
		out.Timings.Total = time.Since(start)
		return out
	}
	if p.Hostnames {
		e.enrich(ctx, p, emit, &out)
	}

	sortRows(out.Rows)
	if out.Status == StatusComplete && out.Failed > 0 {
		out.Status = StatusPartial
	}
	out.Timings.Total = time.Since(start)
	return out
}
