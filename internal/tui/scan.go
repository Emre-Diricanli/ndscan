package tui

import (
	"context"
	"net"
	"strconv"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/Emre-Diricanli/ndscan/internal/config"
	"github.com/Emre-Diricanli/ndscan/internal/engine"
	"github.com/Emre-Diricanli/ndscan/internal/ui"
)

// scanParams is the resolved configuration captured from the form.
type scanParams struct {
	sshTarget   string
	targets     []string
	preset      string
	ports       string
	showMac     bool
	showVendors bool
	rootScan    bool
	concurrency int
	hostTimeout time.Duration
}

// ----- messages streamed from the scan goroutine into the Bubble Tea loop -----

type phaseMsg struct {
	phase string // "discover" | "mac" | "scan" | "enrich"
	done  int
	total int
}

// hostRowMsg carries one host's parsed rows the moment its scan finishes.
type hostRowMsg struct {
	rows []ui.Row
}

type doneMsg struct {
	rows      []ui.Row
	failed    int
	elapsed   time.Duration
	cancelled bool
	diff      map[string]config.HostDiff
	timings   phaseTimings
	firstErr  error
	fallbacks int
}

type phaseTimings struct {
	discovery  time.Duration
	enrichment time.Duration
	ports      time.Duration
}

type errMsg struct{ err error }

// listen blocks on the event channel and forwards the next message into the
// Bubble Tea runtime. It is re-issued from Update until a terminal message
// (doneMsg / errMsg) arrives.
func listen(ch <-chan tea.Msg) tea.Cmd {
	return func() tea.Msg { return <-ch }
}

// nmapAvailable reports whether a scan can proceed for the given SSH target
// ("" = locally). Remote availability is left to the SSH side to report.
//
// Local scans no longer require nmap: discovery and the quick-preset port scan
// both run natively (see internal/sweep). nmap is only needed for the presets
// that use its fingerprinting, so its absence must not block a scan outright.
func nmapAvailable(sshTarget string) bool {
	// Remote: the SSH side reports its own missing-nmap error.
	// Local: the native scanner handles discovery and quick port scans, so a
	// missing nmap only limits the fingerprinting presets, not scanning itself.
	return true
}

// runScan launches the scan in a background goroutine, returning the channel
// that progress and result messages are delivered on, plus a cancel func.
//
// The pipeline itself — discover, merge the ARP cache, scan ports, enrich
// hostnames — lives in internal/engine; this adapter translates scanParams
// into an engine.Plan and engine events into the Bubble Tea messages above.
func runScan(p scanParams) (<-chan tea.Msg, context.CancelFunc) {
	ch := make(chan tea.Msg, 64)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)

	go func() {
		defer close(ch)
		defer cancel()

		plan := engine.Plan{
			SSHTarget:   p.sshTarget,
			Targets:     p.targets,
			Preset:      p.preset,
			Ports:       p.ports,
			ShowMAC:     p.showMac,
			ShowVendors: p.showVendors,
			RootScan:    p.rootScan,
			Concurrency: p.concurrency,
			HostTimeout: p.hostTimeout,
			// Fast is a preference, not a guarantee: the engine runs the
			// native sweep only where it is viable (not over SSH) and reports
			// what actually ran via Outcome.Fast, which feeds the history key.
			Fast: true,
			// The TUI has always resolved hostnames once the rows are built.
			Hostnames: true,
			// Ask the network what it calls itself: the map is far more
			// useful with "Living-Room-TV" than another bare address.
			Multicast: true,
		}

		emit := func(e engine.Event) {
			switch e.Kind {
			case engine.EventPhase:
				// Non-blocking: the sweep fans out across thousands of
				// goroutines, and a full channel (or a cancelled scan whose
				// reader has stopped) must never stall them.
				select {
				case ch <- phaseMsg{phase: string(e.Phase), done: e.Done, total: e.Total}:
				default:
				}
			case engine.EventRows:
				ch <- hostRowMsg{rows: e.Rows}
			case engine.EventRowsUpdated:
				// Rows revised after the fact — hostname enrichment filling a
				// column on hosts already on screen. The running screen appends
				// what it receives, so these are dropped rather than drawn
				// twice; the final set arrives with doneMsg regardless.
			}
		}

		out := engine.New().Run(ctx, plan, emit)
		if out.Status == engine.StatusFailed {
			ch <- errMsg{err: out.Err}
			return
		}

		// History: only a complete, non-empty run may become the baseline that
		// later scans are compared against — a cancelled, partial, or empty run
		// is indistinguishable from a network where everything vanished, and
		// saving it would make the next scan report the whole network as new.
		// The key carries Outcome.Fast because the native sweep and an nmap
		// scan legitimately find different hosts.
		key := out.ScanKey(plan)
		prev := config.LoadHistory(key)
		var diff map[string]config.HostDiff
		if out.Comparable() {
			cur := out.Snapshots()
			diff = config.Diff(prev, cur)
			_ = config.SaveHistory(key, cur)
		}
		ch <- doneMsg{
			rows:      out.Rows,
			failed:    out.Failed,
			elapsed:   out.Timings.Total,
			cancelled: out.Status == engine.StatusCancelled,
			diff:      diff,
			timings: phaseTimings{
				discovery:  out.Timings.Discovery,
				enrichment: out.Timings.Enrichment,
				ports:      out.Timings.Ports,
			},
			firstErr:  out.FirstErr,
			fallbacks: out.Fallbacks,
		}
	}()

	return ch, cancel
}

// parseTargets splits a raw target string, peeling off a leading "user@host"
// SSH jump target if present.
func parseTargets(raw string) (sshTarget string, targets []string) {
	fields := strings.Fields(raw)
	if len(fields) == 0 {
		return "", nil
	}
	if strings.Contains(fields[0], "@") && !strings.Contains(fields[0], "/") {
		return fields[0], fields[1:]
	}
	return "", fields
}

// localCIDR guesses the primary local IPv4 network (e.g. "192.168.1.0/24")
// for prefilling the targets field. Returns "" if none found.
func localCIDR() string {
	ifaces, err := net.Interfaces()
	if err != nil {
		return ""
	}
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			ipn, ok := a.(*net.IPNet)
			if !ok || ipn.IP.To4() == nil {
				continue
			}
			ones, _ := ipn.Mask.Size()
			return ipn.IP.Mask(ipn.Mask).String() + "/" + strconv.Itoa(ones)
		}
	}
	return ""
}
