package web

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/Emre-Diricanli/ndscan/internal/config"
	"github.com/Emre-Diricanli/ndscan/internal/engine"
	"github.com/Emre-Diricanli/ndscan/internal/netinfo"
	"github.com/Emre-Diricanli/ndscan/internal/topology"
	"github.com/Emre-Diricanli/ndscan/internal/ui"
)

// newTestServer starts a server whose guard allowlist matches its own random
// test port, so requests from the test client look same-origin.
func newTestServer(t *testing.T) *httptest.Server {
	t.Helper()
	return startServer(t, NewServer("test"))
}

func startServer(t *testing.T, s *Server) *httptest.Server {
	t.Helper()
	srv := httptest.NewUnstartedServer(nil)
	addr := srv.Listener.Addr().String()
	srv.Config.Handler = s.Handler(addr)
	srv.Start()
	t.Cleanup(srv.Close)
	return srv
}

// postJSON sends a same-origin JSON POST, as the browser frontend would.
func postJSON(t *testing.T, srv *httptest.Server, path, body string) *http.Response {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, srv.URL+path, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", srv.URL)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

func TestState_EmptyBeforeAnyScan(t *testing.T) {
	srv := newTestServer(t)
	resp, err := http.Get(srv.URL + "/api/state")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}

	var got stateResponse
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.Version != "test" {
		t.Errorf("version = %q", got.Version)
	}
	if got.Scanning {
		t.Error("should not be scanning before any request")
	}
	// The contract says topology is null before the first scan.
	if got.Topology != nil {
		t.Errorf("topology should be null before a scan, got %+v", got.Topology)
	}
	// targets must be [] not null, so the frontend can iterate safely.
	if got.Targets == nil {
		t.Error("targets should be an empty array, not null")
	}
}

func TestScan_RejectsBadRequests(t *testing.T) {
	srv := newTestServer(t)
	cases := []struct {
		name, body string
		want       int
	}{
		{"malformed json", `{`, http.StatusBadRequest},
		{"no targets", `{"targets":[]}`, http.StatusBadRequest},
		{"missing targets", `{}`, http.StatusBadRequest},
		{"bad preset", `{"targets":["127.0.0.1"],"preset":"nope"}`, http.StatusBadRequest},
	}
	for _, c := range cases {
		resp := postJSON(t, srv, "/api/scan", c.body)
		resp.Body.Close()
		if resp.StatusCode != c.want {
			t.Errorf("%s: status = %d, want %d", c.name, resp.StatusCode, c.want)
		}
	}
}

func TestCancel_ConflictsWhenIdle(t *testing.T) {
	srv := newTestServer(t)
	resp := postJSON(t, srv, "/api/cancel", "{}")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusConflict {
		t.Errorf("cancel while idle = %d, want 409", resp.StatusCode)
	}
}

// A scan of loopback should run end to end and leave state populated.
func TestScan_EndToEnd(t *testing.T) {
	s := NewServer("test")
	srv := startServer(t, s)

	resp := postJSON(t, srv, "/api/scan", `{"targets":["127.0.0.1"],"fast":true}`)
	resp.Body.Close()
	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("scan start = %d, want 202", resp.StatusCode)
	}

	deadline := time.Now().Add(60 * time.Second)
	for time.Now().Before(deadline) {
		s.mu.RLock()
		done := !s.scanning && s.topo != nil
		s.mu.RUnlock()
		if done {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}

	s.mu.RLock()
	scanning, topo, last := s.scanning, s.topo, s.lastScan
	s.mu.RUnlock()
	if scanning {
		t.Fatal("scan did not finish within 60s")
	}
	if topo == nil {
		t.Fatal("topology not populated after scan")
	}
	if last == nil {
		t.Error("lastScan not recorded")
	}
}

// Starting a second scan while one runs must conflict, not run both.
func TestScan_RejectsConcurrent(t *testing.T) {
	s := NewServer("test")
	srv := startServer(t, s)

	s.mu.Lock()
	s.scanning = true
	s.cancel = func() {}
	s.mu.Unlock()

	resp := postJSON(t, srv, "/api/scan", `{"targets":["127.0.0.1"]}`)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusConflict {
		t.Errorf("concurrent scan = %d, want 409", resp.StatusCode)
	}
}

// SSE must deliver published events in the documented framing.
func TestEvents_StreamsPublishedEvents(t *testing.T) {
	s := NewServer("test")
	srv := startServer(t, s)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, srv.URL+"/api/events", nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if ct := resp.Header.Get("Content-Type"); ct != "text/event-stream" {
		t.Errorf("content-type = %q, want text/event-stream", ct)
	}

	// Give the subscriber time to register before publishing.
	time.Sleep(150 * time.Millisecond)
	s.bus.publish("phase", map[string]any{"phase": "discover", "done": 1, "total": 2})

	sawEvent, sawData := false, false
	sc := bufio.NewScanner(resp.Body)
	deadline := time.Now().Add(5 * time.Second)
	for sc.Scan() && time.Now().Before(deadline) {
		line := sc.Text()
		if strings.HasPrefix(line, "event: phase") {
			sawEvent = true
		}
		if strings.HasPrefix(line, "data: ") && strings.Contains(line, "discover") {
			sawData = true
		}
		if sawEvent && sawData {
			break
		}
	}
	if !sawEvent || !sawData {
		t.Errorf("SSE framing wrong: sawEvent=%v sawData=%v", sawEvent, sawData)
	}
}

// A slow subscriber must never block publishing — the scan comes first.
func TestEventBus_DoesNotBlockOnSlowSubscriber(t *testing.T) {
	b := newEventBus()
	id, _ := b.subscribe() // never drained
	defer b.unsubscribe(id)

	done := make(chan struct{})
	go func() {
		for i := 0; i < 1000; i++ {
			b.publish("phase", map[string]int{"n": i})
		}
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("publish blocked on a slow subscriber")
	}
}

// The DTO conversion must match the frozen contract's field names.
func TestToTopologyDTO_MatchesContract(t *testing.T) {
	m := topology.Build(
		[]ui.Row{{
			IP: "192.168.1.1", Host: "router", Up: true, RTT: "3ms",
			PortDetails: []ui.PortInfo{{Port: 443, Proto: "tcp", Service: "https", Severity: "info"}},
		}},
		topology.Input{
			Locals:  []netinfo.Network{{Interface: "en0", CIDR: "192.168.1.0/24", Addr: "192.168.1.5"}},
			Gateway: netinfo.Gateway{IP: "192.168.1.1"},
		},
	)
	b, err := json.Marshal(toTopologyDTO(m))
	if err != nil {
		t.Fatal(err)
	}
	js := string(b)
	for _, key := range []string{
		`"gateway"`, `"segments"`, `"cidr"`, `"interface"`, `"nodes"`,
		`"isGateway"`, `"host"`, `"ip"`, `"hostname"`, `"ports"`, `"service"`,
	} {
		if !strings.Contains(js, key) {
			t.Errorf("contract key %s missing from JSON: %s", key, js)
		}
	}
	// Nodes must serialize as an array, never null.
	if strings.Contains(js, `"nodes":null`) {
		t.Errorf("nodes must be [] not null: %s", js)
	}
}

// The state endpoint must carry the honesty flags through to the browser:
// an inferred boundary marked as such, and orphans present at all — a host
// that answered must never be dropped by the web layer.
func TestState_ServesInferredAndOrphans(t *testing.T) {
	s := NewServer("test")
	s.topo = &topology.Map{
		Segments: []topology.Segment{{CIDR: "192.0.2.0/24", Inferred: true}},
		Orphans:  []topology.Node{{Row: ui.Row{IP: "203.0.113.10", Up: true}}},
	}
	srv := startServer(t, s)
	resp, err := http.Get(srv.URL + "/api/state")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	js := string(body)
	for _, want := range []string{`"inferred":true`, `"orphans"`, `"ip":"203.0.113.10"`} {
		if !strings.Contains(js, want) {
			t.Errorf("state JSON missing %s: %s", want, js)
		}
	}
}

// The frontend route must respond even before the SPA is embedded.
func TestFrontend_RespondsWithoutEmbeddedApp(t *testing.T) {
	srv := newTestServer(t)
	resp, err := http.Get(srv.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("GET / = %d, want 200", resp.StatusCode)
	}
}

func TestExport(t *testing.T) {
	now := time.Date(2026, 8, 5, 19, 54, 21, 0, time.UTC)
	cases := []struct {
		format, contentType, contains string
	}{
		{"json", "application/json", `"ip": "192.0.2.1"`},
		{"csv", "text/csv", "ip,hostname,mac,vendor,os,up,ports"},
		{"md", "text/markdown", "# Network scan"},
		{"html", "text/html", "<!doctype html>"},
	}
	for _, tc := range cases {
		t.Run(tc.format, func(t *testing.T) {
			s := NewServer("test")
			s.lastScan = &now
			s.targets = []string{"192.0.2.0/24"}
			s.preset = "quick"
			s.rows = []ui.Row{{IP: "192.0.2.1", Host: "host", Up: true, Ports: []string{"22/tcp ssh"}}}
			srv := startServer(t, s)
			resp, err := http.Get(srv.URL + "/api/export?format=" + tc.format)
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()
			body, _ := io.ReadAll(resp.Body)
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("status = %d: %s", resp.StatusCode, body)
			}
			if !strings.HasPrefix(resp.Header.Get("Content-Type"), tc.contentType) {
				t.Errorf("content-type = %q", resp.Header.Get("Content-Type"))
			}
			if got := resp.Header.Get("Content-Disposition"); got != `attachment; filename="ndscan-20260805-195421.`+tc.format+`"` {
				t.Errorf("content-disposition = %q", got)
			}
			if !strings.Contains(string(body), tc.contains) {
				t.Errorf("body missing %q: %s", tc.contains, body)
			}
		})
	}
}

func TestExportErrors(t *testing.T) {
	cases := []struct {
		name, path string
		status     int
	}{
		{"no scan", "/api/export?format=json", http.StatusConflict},
		{"missing format", "/api/export", http.StatusBadRequest},
		{"bad format", "/api/export?format=pdf", http.StatusBadRequest},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := newTestServer(t)
			resp, err := http.Get(srv.URL + tc.path)
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()
			if resp.StatusCode != tc.status {
				t.Errorf("status = %d, want %d", resp.StatusCode, tc.status)
			}
		})
	}
}

func TestHistory(t *testing.T) {
	s := NewServer("test")
	s.hasPrevious = true
	s.previous = []config.HostSnapshot{{IP: "192.0.2.1", Ports: []string{"22/tcp ssh"}}}
	s.diff = map[string]config.HostDiff{"192.0.2.1": {PortsOpened: []string{"443"}, PortsClosed: []string{"22"}}, "192.0.2.2": {New: true}}
	srv := startServer(t, s)
	resp, err := http.Get(srv.URL + "/api/history")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var got historyResponse
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatal(err)
	}
	if !got.HasPrevious || len(got.Previous) != 1 {
		t.Fatalf("history = %+v", got)
	}
	if !got.Diff["192.0.2.2"].New || got.Diff["192.0.2.1"].PortsOpened[0] != "443" {
		t.Errorf("diff = %+v", got.Diff)
	}
}

func TestFinishScanPersistsAndDiffsHistory(t *testing.T) {
	t.Setenv("NDSCAN_CONFIG_DIR", t.TempDir())
	targets := []string{"192.0.2.1"}
	s := NewServer("test")
	s.finishScan(okOutcome([]ui.Row{{IP: "192.0.2.1", Up: true, Ports: []string{"22/tcp ssh"}}}), webPlan(targets), time.Now(), netSnapshot{})
	if got := config.LoadHistory(config.ScanKey{Targets: targets, Ports: s.portsFor("quick"), Preset: "quick"}); len(got) != 1 {
		t.Fatalf("saved history = %+v", got)
	}
	s.finishScan(okOutcome([]ui.Row{{IP: "192.0.2.1", Up: true, Ports: []string{"443/tcp https"}}}), webPlan(targets), time.Now(), netSnapshot{})
	if !s.hasPrevious || s.diff["192.0.2.1"].PortsOpened[0] != "443" || s.diff["192.0.2.1"].PortsClosed[0] != "22" {
		t.Errorf("history state: hasPrevious=%v diff=%+v", s.hasPrevious, s.diff)
	}
}

func TestDiscoverRejectsNonIPs(t *testing.T) {
	cases := []string{"router.local", "192.0.2.0/24", "--script=evil", "127.0.0.1;id", ""}
	for _, ip := range cases {
		t.Run(ip, func(t *testing.T) {
			srv := newTestServer(t)
			body, _ := json.Marshal(map[string]string{"ip": ip})
			resp := postJSON(t, srv, "/api/discover", string(body))
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusBadRequest {
				t.Errorf("status = %d, want 400", resp.StatusCode)
			}
		})
	}
}

// Cancelling a scan used to write its (empty) results as the new baseline, so
// the next scan reported the entire network as new. This is the regression that
// test exists for: the web saved unconditionally while the TUI did not.
func TestFinishScanDoesNotPersistIncompleteRuns(t *testing.T) {
	targets := []string{"192.0.2.1"}
	good := []ui.Row{{IP: "192.0.2.1", Up: true, Ports: []string{"22/tcp ssh"}}}
	plan := webPlan(targets)

	cases := []struct {
		name string
		out  engine.Outcome
	}{
		{"cancelled with no results", engine.Outcome{Status: engine.StatusCancelled}},
		{"cancelled with partial results", engine.Outcome{Status: engine.StatusCancelled, Rows: good}},
		{"hosts failed to scan", engine.Outcome{Status: engine.StatusPartial, Rows: good, Failed: 2}},
		{"outright failure", engine.Outcome{Status: engine.StatusFailed, Rows: good}},
		// Finding nothing is nearly always a lost network, not an empty one.
		{"found nothing", engine.Outcome{Status: engine.StatusComplete}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("NDSCAN_CONFIG_DIR", t.TempDir())
			s := NewServer("test")

			// Establish a good baseline first, so the test proves the bad run is
			// rejected rather than merely that nothing was ever written.
			s.finishScan(okOutcome(good), plan, time.Now(), netSnapshot{})
			base := config.LoadHistory(engine.Outcome{}.ScanKey(plan))
			if len(base) != 1 {
				t.Fatalf("baseline not established: %+v", base)
			}

			s.finishScan(tc.out, plan, time.Now(), netSnapshot{})

			if got := config.LoadHistory(engine.Outcome{}.ScanKey(plan)); !reflect.DeepEqual(got, base) {
				t.Errorf("incomplete run overwrote the baseline: %+v", got)
			}
			if len(s.diff) != 0 {
				t.Errorf("incomplete run produced a diff: %+v", s.diff)
			}
		})
	}
}

// The fast native sweep and an nmap scan find different hosts, so they must not
// be compared against each other.
func TestFinishScanSeparatesFastAndNmapHistory(t *testing.T) {
	t.Setenv("NDSCAN_CONFIG_DIR", t.TempDir())
	targets := []string{"192.0.2.1"}
	s := NewServer("test")

	nmapRun := okOutcome([]ui.Row{{IP: "192.0.2.1", Up: true}})
	fastRun := okOutcome([]ui.Row{{IP: "192.0.2.9", Up: true}})
	fastRun.Fast = true

	s.finishScan(nmapRun, webPlan(targets), time.Now(), netSnapshot{})
	s.finishScan(fastRun, webPlan(targets), time.Now(), netSnapshot{})

	// The fast run is the first of its kind, so it has no previous scan to
	// compare against and must not report the nmap run's host as departed.
	if len(s.diff) != 0 {
		t.Errorf("fast scan diffed against nmap history: %+v", s.diff)
	}
}

// webPlan mirrors the plan runScan builds, so tests file history under the same
// key the server really uses.
func webPlan(targets []string) engine.Plan {
	return NewServer("test").scanPlan(targets, "quick", false)
}

// okOutcome is a clean, complete run of the given rows.
func okOutcome(rows []ui.Row) engine.Outcome {
	return engine.Outcome{Status: engine.StatusComplete, Rows: rows}
}

// The history key needs a discriminator for the preset, because the web has no
// port box and every preset would otherwise share one baseline. That
// discriminator is a label, not a port list — feeding it to the scanner asks
// for ports named "preset:quick", which matches nothing and silently scans no
// ports at all.
func TestScanPlanDoesNotPassTheHistoryLabelAsPorts(t *testing.T) {
	plan := webPlan([]string{"192.0.2.1"})

	if plan.Ports != "" {
		t.Errorf("Plan.Ports = %q, want empty so the preset chooses", plan.Ports)
	}
	if plan.HistoryPorts == "" {
		t.Error("the preset must still reach the history key")
	}
	// The key must carry the discriminator so two presets never share a baseline.
	if got := (engine.Outcome{}).ScanKey(plan); got.Ports != plan.HistoryPorts {
		t.Errorf("ScanKey ports = %q, want the history label %q", got.Ports, plan.HistoryPorts)
	}
}
