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
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Emre-Diricanli/ndscan/internal/config"
	"github.com/Emre-Diricanli/ndscan/internal/enrich"
	"github.com/Emre-Diricanli/ndscan/internal/netinfo"
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
	watch       watchState
	oui         vendor.DB

	bus *eventBus
}

// NewServer returns a Server ready to be mounted with Handler.
//
// The OUI database is loaded once here rather than per scan: it holds ~39k
// prefixes, and resolving vendor names is the difference between a map of bare
// IPs and one that tells you a host is a Ubiquiti AP or an Apple laptop.
func NewServer(version string) *Server {
	return &Server{version: version, bus: newEventBus(), oui: vendor.LoadDefault()}
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

	s.mu.Lock()
	if s.scanning {
		s.mu.Unlock()
		writeErr(w, http.StatusConflict, "a scan is already running")
		return
	}
	// Detached from the request context: the scan must outlive the POST that
	// started it, since progress is delivered separately over SSE.
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	s.scanning = true
	s.targets = req.Targets
	s.cancel = cancel
	s.mu.Unlock()

	go s.runScan(ctx, cancel, req.Targets, preset, fast)
	writeJSON(w, http.StatusAccepted, map[string]bool{"started": true})
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
	start := time.Now()
	defer func() {
		cancel()
		s.mu.Lock()
		s.scanning = false
		s.cancel = nil
		s.mu.Unlock()
	}()

	runner := scan.NewLocalRunner()
	// Batch as the TUI does: without BatchSize a non-fast scan runs one nmap
	// process per host, up to 64 concurrent at ~10-40MB RSS each. DiscardResults
	// keeps the raw XML from being retained after OnResult has consumed it.
	cfg := scan.Config{Preset: preset, Concurrency: 64, HostTimeout: 20 * time.Second, BatchSize: 16, DiscardResults: true}

	discover := newPhaseThrottle(s.bus, "discover", 100*time.Millisecond)
	s.bus.publish("phase", map[string]any{"phase": "discover", "done": 0, "total": 0})

	var live []string
	var macs map[string]string
	var err error
	if fast && scan.NativeDiscoverySupported(runner) {
		live, macs, err = scan.NativeDiscovery(ctx, targets, runner, discover.update)
	} else {
		live, err = scan.HostDiscovery(ctx, targets, runner)
	}
	discover.flush()
	if err != nil {
		s.bus.publish("error", map[string]string{"error": err.Error()})
		return
	}
	if ctx.Err() != nil {
		s.finishScan(nil, targets, preset, start, true)
		return
	}

	arp := scan.ARPCache(ctx, runner)
	live = scan.MergeARPHosts(live, targets, arp)
	if macs == nil {
		macs = map[string]string{}
	}
	for ip, mac := range arp {
		if _, ok := macs[ip]; !ok {
			macs[ip] = mac
		}
	}

	progress := newPhaseThrottle(s.bus, "scan", 100*time.Millisecond)
	s.bus.publish("phase", map[string]any{"phase": "scan", "done": 0, "total": len(live)})

	// Both paths stream through OnResult so a host reaches the browser the
	// moment it resolves, rather than after the slowest address in the scan has
	// finished timing out. It fires from worker goroutines, so the row slice
	// needs the mutex.
	var (
		mu   sync.Mutex
		rows []ui.Row
	)
	cfg.OnResult = func(r scan.HostResult) {
		built := ui.BuildRows([]scan.HostResult{r}, s.oui, true, true, macs)
		if len(built) == 0 {
			return
		}
		mu.Lock()
		rows = append(rows, built...)
		mu.Unlock()
		for _, row := range built {
			s.bus.publish("host", toHostDTO(row))
		}
	}
	cfg.Progress = progress.update

	if fast && scan.NativePortScanViable(cfg, runner) {
		scan.NativePortScan(ctx, live, cfg, progress.update)
	} else if _, err = scan.ScanHosts(ctx, live, cfg, runner); err != nil {
		s.bus.publish("error", map[string]string{"error": err.Error()})
		return
	}
	progress.flush()

	mu.Lock()
	final := append([]ui.Row(nil), rows...)
	mu.Unlock()
	sort.Slice(final, func(i, j int) bool { return ui.IPLess(final[i].IP, final[j].IP) })

	// Hostnames last: rows are already on screen by now, so this only fills a
	// column rather than delaying anything. Bounded internally, and a miss just
	// leaves the field blank.
	if ctx.Err() == nil {
		ui.ApplyHostnames(final, enrich.LookupPTR(ctx, rowIPs(final), enrich.Config{}))
		for _, row := range final {
			s.bus.publish("host", toHostDTO(row))
		}
	}
	s.finishScan(final, targets, preset, start, ctx.Err() != nil)
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
func (s *Server) finishScan(rows []ui.Row, targets []string, preset string, start time.Time, cancelled bool) {
	m := topology.Build(rows, netinfo.Locals(), netinfo.DefaultGateway())
	now := time.Now()
	cur := make([]config.HostSnapshot, 0, len(rows))
	for _, row := range rows {
		cur = append(cur, config.HostSnapshot{IP: row.IP, Host: row.Host, Ports: row.Ports})
	}
	prev := config.LoadHistory(targets, "", preset)
	diff := config.Diff(prev, cur)
	_ = config.SaveHistory(targets, "", preset, cur)

	s.mu.Lock()
	s.topo = &m
	s.lastScan = &now
	s.rows = append([]ui.Row(nil), rows...)
	s.preset = preset
	s.previous = append([]config.HostSnapshot(nil), prev...)
	s.hasPrevious = prev != nil
	s.diff = diff
	s.mu.Unlock()

	openPorts := 0
	for _, r := range rows {
		openPorts += len(r.PortDetails)
	}
	s.bus.publish("done", map[string]any{
		"hosts":     len(rows),
		"openPorts": openPorts,
		"elapsedMs": time.Since(start).Milliseconds(),
		"cancelled": cancelled,
	})
}

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
