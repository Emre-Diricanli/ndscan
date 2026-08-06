package web

import (
	"encoding/json"
	"net/http"
	"sync"
	"testing"
	"time"
)

func decodeWatch(t *testing.T, resp *http.Response) watchResponse {
	t.Helper()
	defer resp.Body.Close()
	var w watchResponse
	if err := json.NewDecoder(resp.Body).Decode(&w); err != nil {
		t.Fatalf("decode watch response: %v", err)
	}
	return w
}

func TestWatchAndManualScan_OnlyOneAdmitted(t *testing.T) {
	s := NewServer("test")
	s.mu.Lock()

	start := make(chan struct{})
	admitted := make(chan bool, 2)
	var ready sync.WaitGroup
	ready.Add(2)
	go func() {
		ready.Done()
		<-start
		_, ok := s.startWatchScan([]string{"127.0.0.1"}, "quick", true)
		admitted <- ok
	}()
	go func() {
		ready.Done()
		<-start
		admitted <- s.startScan([]string{"127.0.0.1"}, "quick", true)
	}()
	ready.Wait()
	close(start)
	s.mu.Unlock()

	winners := 0
	for range 2 {
		if <-admitted {
			winners++
		}
	}
	if winners != 1 {
		t.Fatalf("admitted %d concurrent scans, want exactly one", winners)
	}
	s.mu.Lock()
	cancel := s.cancel
	running := s.scanning
	s.mu.Unlock()
	if !running || cancel == nil {
		t.Fatal("winning scan did not retain its cancellation state")
	}
	cancel()
}

func TestWatch_EnableAndDisable(t *testing.T) {
	s := NewServer("test")
	srv := startServer(t, s)

	got := decodeWatch(t, postJSON(t, srv, "/api/watch",
		`{"enabled":true,"intervalSec":60,"targets":["127.0.0.1"]}`))
	if !got.Enabled {
		t.Fatal("watch should be enabled")
	}
	if got.IntervalSec != 60 {
		t.Errorf("interval = %d, want 60", got.IntervalSec)
	}
	if got.NextAt == "" {
		t.Error("nextAt should be set when watching")
	}

	s.mu.RLock()
	enabled := s.watch.enabled
	s.mu.RUnlock()
	if !enabled {
		t.Error("server watch state not enabled")
	}

	got = decodeWatch(t, postJSON(t, srv, "/api/watch", `{"enabled":false}`))
	if got.Enabled {
		t.Error("watch should be disabled")
	}
	s.mu.RLock()
	enabled = s.watch.enabled
	s.mu.RUnlock()
	if enabled {
		t.Error("server watch state still enabled after disable")
	}
}

// Watch mode is a scan on a timer, so it must reject the same bad input a
// manual scan does — otherwise it would fail silently on every tick.
func TestWatch_ValidatesTargets(t *testing.T) {
	srv := newTestServer(t)
	cases := []string{
		`{"enabled":true,"targets":["--script=evil"],"intervalSec":60}`,
		`{"enabled":true,"targets":["example.com"],"intervalSec":60}`,
		`{"enabled":true,"targets":["127.0.0.1"],"preset":"bogus","intervalSec":60}`,
	}
	for _, body := range cases {
		resp := postJSON(t, srv, "/api/watch", body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusBadRequest {
			t.Errorf("body %s = %d, want 400", body, resp.StatusCode)
		}
	}
}

// Enabling with no targets and no prior scan has nothing to watch.
func TestWatch_RequiresTargets(t *testing.T) {
	srv := newTestServer(t)
	resp := postJSON(t, srv, "/api/watch", `{"enabled":true,"intervalSec":60}`)
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("watch with no targets = %d, want 400", resp.StatusCode)
	}
}

// A too-frequent interval is clamped rather than accepted: watch mode should
// notice changes, not saturate the network.
func TestWatch_ClampsShortInterval(t *testing.T) {
	srv := newTestServer(t)
	got := decodeWatch(t, postJSON(t, srv, "/api/watch",
		`{"enabled":true,"intervalSec":1,"targets":["127.0.0.1"]}`))
	if got.IntervalSec != int(minWatchInterval.Seconds()) {
		t.Errorf("interval = %d, want clamped to %d", got.IntervalSec, int(minWatchInterval.Seconds()))
	}
}

// Re-enabling must supersede the previous loop, not leave two running.
func TestWatch_RestartSupersedesPreviousLoop(t *testing.T) {
	s := NewServer("test")
	srv := startServer(t, s)

	postJSON(t, srv, "/api/watch", `{"enabled":true,"intervalSec":60,"targets":["127.0.0.1"]}`).Body.Close()
	s.mu.RLock()
	firstGen := s.watch.gen
	s.mu.RUnlock()

	postJSON(t, srv, "/api/watch", `{"enabled":true,"intervalSec":90,"targets":["127.0.0.1"]}`).Body.Close()
	s.mu.RLock()
	secondGen := s.watch.gen
	interval := s.watch.interval
	s.mu.RUnlock()

	if secondGen == firstGen {
		t.Error("restart should bump the generation so the old loop exits")
	}
	if interval != 90*time.Second {
		t.Errorf("interval = %v, want 90s", interval)
	}
}

// Watch status must appear in /api/state so a reloading browser can resync.
func TestState_IncludesWatchStatus(t *testing.T) {
	s := NewServer("test")
	srv := startServer(t, s)
	postJSON(t, srv, "/api/watch", `{"enabled":true,"intervalSec":60,"targets":["127.0.0.1"]}`).Body.Close()

	resp, err := http.Get(srv.URL + "/api/state")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var st stateResponse
	if err := json.NewDecoder(resp.Body).Decode(&st); err != nil {
		t.Fatal(err)
	}
	if !st.Watch.Enabled {
		t.Error("state should report watch enabled")
	}
	if st.Watch.IntervalSec != 60 {
		t.Errorf("state watch interval = %d, want 60", st.Watch.IntervalSec)
	}
}

func TestValidPreset(t *testing.T) {
	for _, p := range []string{"quick", "smart", "default", "udp", "deep"} {
		if !validPreset(p) {
			t.Errorf("validPreset(%q) = false", p)
		}
	}
	for _, p := range []string{"", "Quick", "fast", "bogus"} {
		if validPreset(p) {
			t.Errorf("validPreset(%q) = true", p)
		}
	}
}
