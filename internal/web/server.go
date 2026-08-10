// Package web serves ndscan's optional browser interface: a JSON API over the
// same scan engine the CLI and TUI use, plus an embedded single-page frontend.
//
// The server binds to loopback by default and deliberately makes exposing it
// beyond that an explicit choice. A network scanner reachable over the network
// is a remote-controlled scanner, which is a materially different security
// proposition from a local tool.
package web

import (
	"bytes"
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Emre-Diricanli/ndscan/internal/config"
	"github.com/Emre-Diricanli/ndscan/internal/engine"
	"github.com/Emre-Diricanli/ndscan/internal/netinfo"
	"github.com/Emre-Diricanli/ndscan/internal/notify"
	"github.com/Emre-Diricanli/ndscan/internal/report"
	"github.com/Emre-Diricanli/ndscan/internal/scan"
	"github.com/Emre-Diricanli/ndscan/internal/topology"
	"github.com/Emre-Diricanli/ndscan/internal/ui"
	"github.com/Emre-Diricanli/ndscan/internal/vendor"
)

// Server holds the scan state shared between HTTP handlers.
type Server struct {
	version string

	mu          sync.RWMutex
	scanning    bool
	targets     []string
	lastScan    *time.Time
	topo        *topology.Map
	rows        []ui.Row
	preset      string
	previous    []config.HostSnapshot
	diff        map[string]config.HostDiff
	hasPrevious bool
	cancel      context.CancelFunc
	// namesCancel stops an in-flight deferred naming pass. It is separate from
	// cancel because that one belongs to the scan, which has already finished
	// by the time this pass is running.
	namesCancel context.CancelFunc
	watch       watchState
	oui         vendor.DB
	// eng is held rather than constructed per scan so its multicast name cache
	// survives between scans, including watch-mode rescans.
	eng *engine.Engine

	bus *eventBus
}

// NewServer returns a Server ready to be mounted with Handler.
//
// The OUI database is loaded once here rather than per scan: it holds ~39k
// prefixes, and resolving vendor names is the difference between a map of bare
// IPs and one that tells you a host is a Ubiquiti AP or an Apple laptop.
func NewServer(version string) *Server {
	return &Server{version: version, bus: newEventBus(), oui: vendor.LoadDefault(), eng: engine.New()}
}

// Handler returns the HTTP routes: the JSON API plus the embedded frontend,
// wrapped in the Host/Origin guard. addr is the bind address, which determines
// which Host headers are acceptable.
func (s *Server) Handler(addr string) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/state", s.handleState)
	mux.HandleFunc("GET /api/topology", s.handleTopology)
	mux.HandleFunc("GET /api/export", s.handleExport)
	mux.HandleFunc("GET /api/history", s.handleHistory)
	mux.HandleFunc("POST /api/scan", s.handleScan)
	mux.HandleFunc("POST /api/scan/sweep", s.handleSweep)
	mux.HandleFunc("POST /api/discover", s.handleDiscover)
	mux.HandleFunc("POST /api/cancel", s.handleCancel)
	mux.HandleFunc("POST /api/watch", s.handleWatch)
	mux.HandleFunc("GET /api/events", s.handleEvents)
	mux.Handle("/", frontendHandler())
	return guard(mux, addr)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

type stateResponse struct {
	Version  string        `json:"version"`
	Scanning bool          `json:"scanning"`
	Targets  []string      `json:"targets"`
	LastScan *time.Time    `json:"lastScan"`
	Topology *topologyDTO  `json:"topology"`
	Watch    watchResponse `json:"watch"`
	// Suggested lists the networks this machine is attached to, so the UI can
	// offer a target instead of an empty box. The scanner already knows the
	// answer to "what should I scan?" — making the user look up their own
	// subnet is a gap between what we know and what we show.
	Suggested []suggestedNetwork `json:"suggested,omitempty"`
	// Siblings are bounded routed candidates derived passively from the same
	// interface table, so showing the choice never probes the network.
	Siblings []string `json:"siblings,omitempty"`
}

// netSnapshot is the machine's network context captured when a scan starts.
// Carrying it forward keeps the finished map describing the network the scan
// actually ran on, even if the machine roamed before the scan completed.
type netSnapshot struct {
	locals  []netinfo.Network
	gateway netinfo.Gateway
}

// suggestedNetwork is one scannable local network offered as a starting target.
type suggestedNetwork struct {
	CIDR      string `json:"cidr"`
	Interface string `json:"interface"`
	Addr      string `json:"addr"`
}

// suggestedNetworks returns the local networks worth offering as scan targets.
//
// Physical interfaces only: a machine typically has several tunnel and
// link-local interfaces (utun*, awdl*, llw*, bridge*) whose networks are either
// point-to-point, Apple-internal, or virtual. Offering those as targets would
// bury the one network the user actually means, and scanning a /32 tunnel
// endpoint finds nothing.
func suggestedNetworks() []suggestedNetwork {
	out := make([]suggestedNetwork, 0, 2)
	for _, n := range netinfo.Locals() {
		if !scannableInterface(n.Interface) {
			continue
		}
		// A prefix this narrow holds no other hosts, so there is nothing to
		// sweep — typical of VPN and point-to-point links.
		if p, err := netip.ParsePrefix(n.CIDR); err != nil || p.Bits() >= 31 {
			continue
		}
		out = append(out, suggestedNetwork{CIDR: n.CIDR, Interface: n.Interface, Addr: n.Addr})
	}
	return out
}

// scannableInterface reports whether an interface name denotes a real network
// this machine shares with other hosts, rather than a tunnel or a link-local
// virtual interface.
func scannableInterface(name string) bool {
	for _, prefix := range []string{"utun", "awdl", "llw", "bridge", "gif", "stf", "ap"} {
		if strings.HasPrefix(name, prefix) {
			return false
		}
	}
	return true
}

func (s *Server) handleState(w http.ResponseWriter, r *http.Request) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	resp := stateResponse{
		Version:  s.version,
		Scanning: s.scanning,
		Targets:  s.targets,
		LastScan: s.lastScan,
	}
	if resp.Targets == nil {
		resp.Targets = []string{}
	}
	if s.topo != nil {
		d := toTopologyDTO(*s.topo)
		resp.Topology = &d
	}
	resp.Suggested = suggestedNetworks()
	resp.Siblings = netinfo.SiblingCandidates(netinfo.Locals(), nil)
	resp.Watch = watchResponse{
		Enabled:     s.watch.enabled,
		IntervalSec: int(s.watch.interval.Seconds()),
	}
	if s.watch.enabled {
		resp.Watch.NextAt = s.watch.nextAt.UTC().Format(time.RFC3339)
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) handleTopology(w http.ResponseWriter, r *http.Request) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.topo == nil {
		writeJSON(w, http.StatusOK, nil)
		return
	}
	writeJSON(w, http.StatusOK, toTopologyDTO(*s.topo))
}

func (s *Server) handleExport(w http.ResponseWriter, r *http.Request) {
	format := r.URL.Query().Get("format")
	contentTypes := map[string]string{"json": "application/json", "csv": "text/csv", "md": "text/markdown", "html": "text/html"}
	contentType, ok := contentTypes[format]
	if !ok {
		writeErr(w, http.StatusBadRequest, "format must be one of json, csv, md, html")
		return
	}
	s.mu.RLock()
	if s.lastScan == nil {
		s.mu.RUnlock()
		writeErr(w, http.StatusConflict, "no scan has run yet")
		return
	}
	rows := append([]ui.Row(nil), s.rows...)
	targets := append([]string(nil), s.targets...)
	preset, generated := s.preset, *s.lastScan
	s.mu.RUnlock()

	var body []byte
	var err error
	switch format {
	case "json":
		body, err = json.MarshalIndent(rows, "", "  ")
	case "csv":
		var b bytes.Buffer
		cw := csv.NewWriter(&b)
		err = cw.Write([]string{"ip", "hostname", "mac", "vendor", "os", "up", "ports"})
		for _, row := range rows {
			if err == nil {
				err = cw.Write([]string{row.IP, row.Host, row.MAC, row.Vendor, row.OS, strconv.FormatBool(row.Up), strings.Join(row.Ports, "; ")})
			}
		}
		cw.Flush()
		if err == nil {
			err = cw.Error()
		}
		body = b.Bytes()
	default:
		rep := report.Report{Targets: strings.Join(targets, ", "), Preset: preset, Generated: generated.Format("2006-01-02 15:04:05"), Rows: rows}
		if format == "md" {
			body = []byte(rep.Markdown())
		} else {
			body = []byte(rep.HTML())
		}
	}
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "could not render export")
		return
	}
	w.Header().Set("Content-Type", contentType+"; charset=utf-8")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="ndscan-%s.%s"`, generated.Format("20060102-150405"), format))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(body)
}

type historyResponse struct {
	HasPrevious bool                   `json:"hasPrevious"`
	Previous    []config.HostSnapshot  `json:"previous,omitempty"`
	Diff        map[string]historyDiff `json:"diff"`
}

type historyDiff struct {
	New         bool     `json:"new,omitempty"`
	Gone        bool     `json:"gone,omitempty"`
	PortsOpened []string `json:"portsOpened,omitempty"`
	PortsClosed []string `json:"portsClosed,omitempty"`
}

func (s *Server) handleHistory(w http.ResponseWriter, r *http.Request) {
	s.mu.RLock()
	resp := historyResponse{HasPrevious: s.hasPrevious, Previous: append([]config.HostSnapshot(nil), s.previous...), Diff: make(map[string]historyDiff, len(s.diff))}
	for ip, d := range s.diff {
		resp.Diff[ip] = historyDiff{New: d.New, Gone: d.Gone, PortsOpened: d.PortsOpened, PortsClosed: d.PortsClosed}
	}
	s.mu.RUnlock()
	writeJSON(w, http.StatusOK, resp)
}

type discoverRequest struct {
	IP string `json:"ip"`
}

func (s *Server) handleDiscover(w http.ResponseWriter, r *http.Request) {
	var req discoverRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	if _, err := netip.ParseAddr(req.IP); err != nil {
		writeErr(w, http.StatusBadRequest, "ip must be a literal IP address")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 50*time.Second)
	defer cancel()
	runner := scan.NewLocalRunner()
	cfg := scan.Config{Preset: "default", Ports: "1-1024,1433,3306,3389,5432,5900,6379,8080,8443,9200,27017", UseSYN: scan.IsRoot(), Concurrency: 1, HostTimeout: 45 * time.Second, NeedMAC: true}
	results, err := scan.ScanHosts(ctx, []string{req.IP}, cfg, runner)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	rows := ui.BuildRows(results, s.oui, true, true, scan.ARPCache(ctx, runner))
	if len(rows) == 0 {
		writeErr(w, http.StatusNotFound, "host did not return a scan result")
		return
	}
	writeJSON(w, http.StatusOK, toHostDTO(rows[0]))
}

type scanRequest struct {
	Targets []string `json:"targets"`
	Fast    *bool    `json:"fast"`
	Preset  string   `json:"preset"`
}

func (s *Server) handleScan(w http.ResponseWriter, r *http.Request) {
	var req scanRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	// Strict validation: only literal IPs and CIDRs reach the scan engine, so
	// a target can never be smuggled through as a scanner flag or shell token.
	if err := validateTargets(req.Targets); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	preset := req.Preset
	if preset == "" {
		preset = "quick"
	}
	if !validPreset(preset) {
		writeErr(w, http.StatusBadRequest, "invalid preset "+preset)
		return
	}
	fast := true
	if req.Fast != nil {
		fast = *req.Fast
	}

	if !s.startScan(req.Targets, preset, fast) {
		writeErr(w, http.StatusConflict, "a scan is already running")
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]bool{"started": true})
}

// startScan owns the single transition from idle to scanning. Keeping the
// check and state change under one lock prevents manual and routed requests
// from racing each other into two concurrent scans.
func (s *Server) startScan(targets []string, preset string, fast bool) bool {
	_, started := s.startScanDone(targets, preset, fast)
	return started
}

// startScanDone is startScan plus a channel closed when the scan finishes.
//
// Watch mode needs that signal: its interval is the gap *between* scans, so it
// has to wait for one run to end before timing the next. It must not reproduce
// the check-and-set to get it — a second copy of that transition is exactly how
// a manual scan used to slip in beside a watch scan and overwrite the cancel
// function — so the single transition lives here and hands back the signal.
func (s *Server) startScanDone(targets []string, preset string, fast bool) (<-chan struct{}, bool) {
	s.mu.Lock()
	if s.scanning {
		s.mu.Unlock()
		return nil, false
	}
	// Detached from the request context: the scan must outlive the POST that
	// started it, since progress is delivered separately over SSE.
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	s.scanning = true
	s.targets = targets
	s.cancel = cancel
	// The previous scan's naming pass, if still listening, is now describing a
	// host set that is about to be replaced.
	if s.namesCancel != nil {
		s.namesCancel()
		s.namesCancel = nil
	}
	s.mu.Unlock()

	done := make(chan struct{})
	go func() {
		defer close(done)
		s.runScan(ctx, cancel, targets, preset, fast)
	}()
	return done, true
}

func (s *Server) handleCancel(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	cancel := s.cancel
	running := s.scanning
	s.mu.Unlock()

	if !running || cancel == nil {
		writeErr(w, http.StatusConflict, "no scan is running")
		return
	}
	cancel()
	writeJSON(w, http.StatusOK, map[string]bool{"cancelled": true})
}

// runScan executes a scan and publishes progress to SSE subscribers. It always
// clears the scanning flag, so a failure can never wedge the server.
func (s *Server) runScan(ctx context.Context, cancel context.CancelFunc, targets []string, preset string, fast bool) {
	// Capture the network context now, not when the scan finishes. A laptop can
	// change Wi-Fi or drop a VPN mid-scan, and reading the interfaces at the end
	// would label these results with a network they were never taken on.
	locals, gateway := netinfo.Locals(), netinfo.DefaultGateway()
	start := time.Now()
	defer func() {
		cancel()
		s.mu.Lock()
		s.scanning = false
		s.cancel = nil
		s.mu.Unlock()
	}()

	// One throttle per phase: the sweep reports progress from thousands of
	// goroutines, and forwarding every update would flood the SSE stream with
	// more messages than a browser can usefully render.
	discover := newPhaseThrottle(s.bus, "discover", 100*time.Millisecond)
	ports := newPhaseThrottle(s.bus, "scan", 100*time.Millisecond)
	s.bus.publish("phase", map[string]any{"phase": "discover", "done": 0, "total": 0})

	emit := func(e engine.Event) {
		switch e.Kind {
		case engine.EventPhase:
			switch e.Phase {
			case engine.PhaseDiscover:
				discover.update(e.Done, e.Total)
			case engine.PhaseScan:
				if e.Total > 0 && e.Done == 0 {
					discover.flush()
					s.bus.publish("phase", map[string]any{"phase": "scan", "done": 0, "total": e.Total})
					return
				}
				ports.update(e.Done, e.Total)
			}
		case engine.EventRows:
			// Each host reaches the browser the moment it resolves, rather than
			// after the slowest address in the scan has finished timing out.
			for _, row := range e.Rows {
				s.bus.publish("host", toHostDTO(row))
			}
		case engine.EventWarning:
			s.bus.publish("warning", map[string]string{"warning": e.Warning})
		}
	}

	plan := s.scanPlan(targets, preset, fast)
	out := s.eng.Run(ctx, plan, emit)
	discover.flush()
	ports.flush()

	if out.Status == engine.StatusFailed {
		s.bus.publish("error", map[string]string{"error": out.Err.Error()})
		return
	}
	s.finishScan(out, plan, start, netSnapshot{locals: locals, gateway: gateway})
	s.resolveNamesInBackground(out.Rows)
}

// resolveNamesInBackground finishes the naming work the scan skipped.
//
// The scan deferred its multicast pass so the table could appear in about a
// second instead of six; this is the other half, arriving while the user reads
// the results. Rows that gain a better name are republished over SSE as
// updates, which the frontend reconciles by IP.
//
// It deliberately runs after finishScan: the scan is already recorded and the
// UI already says it finished. Names are an improvement to what is on screen,
// not part of the result, and a network with no mDNS speakers must not leave a
// scan looking unfinished for five seconds.
func (s *Server) resolveNamesInBackground(rows []ui.Row) {
	if len(rows) == 0 {
		return
	}
	// A fresh context: runScan's deferred cancel has already fired by the time
	// this matters, and this pass is not part of that scan's lifetime.
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)

	s.mu.Lock()
	// One naming pass at a time. A second scan's results supersede this one's,
	// and names computed for a host set that is no longer displayed would
	// relabel rows the user is not looking at.
	if s.namesCancel != nil {
		s.namesCancel()
	}
	s.namesCancel = cancel
	s.mu.Unlock()

	go func() {
		defer cancel()
		updated, ok := s.eng.ResolveNames(ctx, rows)
		if !ok || ctx.Err() != nil {
			return
		}

		s.mu.Lock()
		// Drop the result if another scan has started: these names describe a
		// host set that is no longer on screen.
		superseded := s.scanning
		if !superseded {
			s.rows = append([]ui.Row(nil), updated...)
		}
		s.mu.Unlock()
		if superseded {
			return
		}

		for _, row := range updated {
			s.bus.publish("host", toHostDTO(row))
		}
	}()
}

// rowIPs collects the addresses from a row set, for lookups keyed by IP.
func rowIPs(rows []ui.Row) []string {
	out := make([]string, 0, len(rows))
	for _, r := range rows {
		out = append(out, r.IP)
	}
	return out
}

// finishScan stores the resulting topology and announces completion.
//
// Whether this run may become the baseline for future change detection is the
// engine's answer, not one reconstructed here. Reconstructing it locally is
// what let a cancelled scan overwrite history: the web had its own copy of the
// rule and the copy was wrong.
func (s *Server) finishScan(out engine.Outcome, plan engine.Plan, start time.Time, net netSnapshot) {
	m := topology.Build(out.Rows, topology.Input{
		Locals:  net.locals,
		Gateway: net.gateway,
		// The scan's own targets are what makes an empty segment meaningful:
		// covered-and-empty is a finding, uncovered is a gap.
		Coverage: plan.Targets,
	})
	now := time.Now()

	// Persist owns the decision about whether this run may update the baseline,
	// and records device identity and the timeline from the same run. The web
	// keeping its own copy of that rule is exactly how a cancelled scan came to
	// overwrite history.
	rec := s.eng.PersistWithGateway(out, plan, start, s.oui, net.gateway.IP)
	// Alerts reach the browser as their own event so the UI can surface a new
	// device or a changed gateway MAC rather than leaving it in a diff table
	// the user has to read to notice.
	// An open tab sees alerts in the page; a closed one has to be told another
	// way. The watch loop's whole purpose is to survive a closed tab, so
	// publishing to SSE alone meant the gateway-MAC canary — the highest
	// severity rule there is — fired into nothing whenever nobody was looking.
	unattended := s.bus.listeners() == 0
	for _, a := range rec.Alerts {
		s.bus.publish("alert", map[string]any{
			"rule": a.Rule, "severity": a.Severity,
			"title": a.Title, "body": a.Body, "subject": a.Subject,
		})
		if unattended {
			// Best effort: a desktop that cannot show notifications must not
			// fail the scan that produced them.
			_ = notify.Send(notify.Notification{Title: a.Title, Message: a.Body})
		}
	}
	for _, w := range rec.Warnings {
		// A failed write is not fatal to this scan but silently disables change
		// detection for every future one, which is indistinguishable from
		// "nothing changed" — so it has to be said out loud.
		s.bus.publish("warning", map[string]string{"warning": w})
	}

	if !rec.Comparable() {
		s.mu.Lock()
		s.topo = &m
		s.lastScan = &now
		s.rows = append([]ui.Row(nil), out.Rows...)
		s.preset = plan.Preset
		s.mu.Unlock()
		s.publishDone(out, start)
		return
	}
	prev, diff := rec.Previous, rec.Diff

	s.mu.Lock()
	s.topo = &m
	s.lastScan = &now
	s.rows = append([]ui.Row(nil), out.Rows...)
	s.preset = plan.Preset
	s.previous = append([]config.HostSnapshot(nil), prev...)
	s.hasPrevious = prev != nil
	s.diff = diff
	s.mu.Unlock()

	s.publishDone(out, start)
}

// publishDone announces the end of a scan. It reports how the run terminated so
// the UI can distinguish "no changes" from "we did not look properly" — the two
// are identical on screen otherwise, and only one of them is good news.
func (s *Server) publishDone(out engine.Outcome, start time.Time) {
	openPorts := 0
	for _, r := range out.Rows {
		openPorts += len(r.PortDetails)
	}
	s.bus.publish("done", map[string]any{
		"hosts":     len(out.Rows),
		"openPorts": openPorts,
		"elapsedMs": time.Since(start).Milliseconds(),
		"status":    out.Status.String(),
		"cancelled": out.Status == engine.StatusCancelled,
		"failed":    out.Failed,
		"partial":   out.Status == engine.StatusPartial,
		// Change detection is only meaningful when this run was trustworthy
		// enough to become the new baseline. Saying so explicitly stops the UI
		// presenting a cancelled scan's empty diff as "nothing changed".
		"comparable": out.Comparable(),
	})
}

// scanPlan builds the plan a web-initiated scan runs under.
//
// Ports is deliberately empty: the web exposes no port box, so the preset owns
// the port selection entirely. The preset still has to reach the history key,
// which is what HistoryPorts is for — passing that label as Ports would ask the
// scanner for ports named "preset:quick" and quietly scan nothing.
func (s *Server) scanPlan(targets []string, preset string, fast bool) engine.Plan {
	return engine.Plan{
		Targets:      targets,
		Preset:       preset,
		HistoryPorts: s.portsFor(preset),
		ShowMAC:      true,
		ShowVendors:  true,
		Concurrency:  64,
		HostTimeout:  20 * time.Second,
		Fast:         fast,
		Hostnames:    true,
		Multicast:    true,
		// The browser can fill a column after the fact, so it does not wait on
		// the multicast listen window — the single largest cost in a fast scan.
		// Results appear as soon as the ports are known and the better names
		// arrive a few seconds later. See runScan's deferred pass.
		DeferMulticast: true,
		IdentifyTLS:    true,
	}
}

// portsFor returns the history-key discriminator for a preset.
//
// The web UI has no free-form port box, so the preset is the whole of the port
// selection. It still has to enter the history key, because a quick scan and a
// deep scan of the same network legitimately find different ports and must not
// be compared against each other.
//
// This is deliberately not a port specification: it is a label, and feeding it
// to a scanner as one would ask for ports named "preset:quick" and find
// nothing. The scan itself passes no ports at all and lets the preset choose.
func (s *Server) portsFor(preset string) string { return "preset:" + preset }

// ListenAndServe starts the HTTP server on addr until ctx is cancelled.
func (s *Server) ListenAndServe(ctx context.Context, addr string) error {
	srv := &http.Server{
		Addr:              addr,
		Handler:           s.Handler(addr),
		ReadHeaderTimeout: 10 * time.Second,
	}
	go func() {
		<-ctx.Done()
		shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutCtx)
	}()
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		return fmt.Errorf("web server: %w", err)
	}
	return nil
}
