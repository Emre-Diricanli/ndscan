// Package web serves ndscan's optional browser interface: a JSON API over the
// same scan engine the CLI and TUI use, plus an embedded single-page frontend.
//
// The server binds to loopback by default and deliberately makes exposing it
// beyond that an explicit choice. A network scanner reachable over the network
// is a remote-controlled scanner, which is a materially different security
// proposition from a local tool.
package web

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/Emre-Diricanli/ndscan/internal/netinfo"
	"github.com/Emre-Diricanli/ndscan/internal/scan"
	"github.com/Emre-Diricanli/ndscan/internal/topology"
	"github.com/Emre-Diricanli/ndscan/internal/ui"
)

// Server holds the scan state shared between HTTP handlers.
type Server struct {
	version string

	mu       sync.RWMutex
	scanning bool
	targets  []string
	lastScan *time.Time
	topo     *topology.Map
	cancel   context.CancelFunc

	bus *eventBus
}

// NewServer returns a Server ready to be mounted with Handler.
func NewServer(version string) *Server {
	return &Server{version: version, bus: newEventBus()}
}

// Handler returns the HTTP routes: the JSON API plus the embedded frontend,
// wrapped in the Host/Origin guard. addr is the bind address, which determines
// which Host headers are acceptable.
func (s *Server) Handler(addr string) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/state", s.handleState)
	mux.HandleFunc("GET /api/topology", s.handleTopology)
	mux.HandleFunc("POST /api/scan", s.handleScan)
	mux.HandleFunc("POST /api/cancel", s.handleCancel)
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
	Version  string       `json:"version"`
	Scanning bool         `json:"scanning"`
	Targets  []string     `json:"targets"`
	LastScan *time.Time   `json:"lastScan"`
	Topology *topologyDTO `json:"topology"`
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
	switch preset {
	case "quick", "default", "udp", "deep":
	default:
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
	cfg := scan.Config{Preset: preset, Concurrency: 64, HostTimeout: 20 * time.Second}

	s.bus.publish("phase", map[string]any{"phase": "discover", "done": 0, "total": 0})

	var live []string
	var macs map[string]string
	var err error
	if fast && scan.NativeDiscoverySupported(runner) {
		live, macs, err = scan.NativeDiscovery(ctx, targets, runner, func(done, total int) {
			s.bus.publish("phase", map[string]any{"phase": "discover", "done": done, "total": total})
		})
	} else {
		live, err = scan.HostDiscovery(ctx, targets, runner)
	}
	if err != nil {
		s.bus.publish("error", map[string]string{"error": err.Error()})
		return
	}
	if ctx.Err() != nil {
		s.finishScan(nil, start, true)
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

	s.bus.publish("phase", map[string]any{"phase": "scan", "done": 0, "total": len(live)})

	var results []scan.HostResult
	if fast && scan.NativePortScanViable(cfg, runner) {
		results = scan.NativePortScan(ctx, live, cfg, func(done, total int) {
			s.bus.publish("phase", map[string]any{"phase": "scan", "done": done, "total": total})
		})
	} else {
		results, err = scan.ScanHosts(ctx, live, cfg, runner)
		if err != nil {
			s.bus.publish("error", map[string]string{"error": err.Error()})
			return
		}
	}

	rows := ui.BuildRows(results, nil, true, false, macs)
	for _, row := range rows {
		s.bus.publish("host", toHostDTO(row))
	}
	s.finishScan(rows, start, ctx.Err() != nil)
}

// finishScan stores the resulting topology and announces completion.
func (s *Server) finishScan(rows []ui.Row, start time.Time, cancelled bool) {
	m := topology.Build(rows, netinfo.Locals(), netinfo.DefaultGateway())
	now := time.Now()

	s.mu.Lock()
	s.topo = &m
	s.lastScan = &now
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
