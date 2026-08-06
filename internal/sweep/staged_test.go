package sweep

import (
	"context"
	"net"
	"strconv"
	"sync"
	"testing"
	"time"
)

// listenerOn starts a loopback listener and returns its port, closed at test end.
func listenerOn(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()
	return ln.Addr().(*net.TCPAddr).Port
}

// The whole point of staging is that an address answering on the first port
// never gets probed on the rest. If it did, we'd be back to addresses x ports.
func TestStagedSweep_StopsProbingAfterFirstAnswer(t *testing.T) {
	open := listenerOn(t)

	var mu sync.Mutex
	probed := 0
	// A port nothing listens on, to pad the port list.
	dead := deadPort(t)

	cfg := withDefaults(Config{
		Ports:   []int{open, dead, dead, dead},
		Timeout: 200 * time.Millisecond,
		Progress: func(done, total int) {
			mu.Lock()
			probed++
			mu.Unlock()
		},
	})

	hits := stagedSweep(context.Background(), []string{"127.0.0.1"}, cfg)
	if len(hits) != 1 {
		t.Fatalf("hits = %d, want 1", len(hits))
	}
	if hits[0].port != open {
		t.Errorf("port = %d, want the open one %d", hits[0].port, open)
	}

	// One real probe round plus the forced terminal progress call. If the
	// remaining three ports had been probed we'd see substantially more.
	mu.Lock()
	defer mu.Unlock()
	if probed > 2 {
		t.Errorf("probed %d times; staging should have stopped after the first answer", probed)
	}
}

// Progress must reach 100% even though staging skips most of the worst-case
// probe count it reports against — otherwise the bar sticks short of full.
func TestStagedSweep_ProgressReachesTotal(t *testing.T) {
	open := listenerOn(t)
	dead := deadPort(t)

	var mu sync.Mutex
	var lastDone, lastTotal int
	cfg := withDefaults(Config{
		Ports:   []int{open, dead, dead},
		Timeout: 200 * time.Millisecond,
		Progress: func(done, total int) {
			mu.Lock()
			lastDone, lastTotal = done, total
			mu.Unlock()
		},
	})

	stagedSweep(context.Background(), []string{"127.0.0.1"}, cfg)

	mu.Lock()
	defer mu.Unlock()
	if lastDone != lastTotal {
		t.Errorf("final progress = %d/%d, want done == total", lastDone, lastTotal)
	}
}

// A refusal proves a host exists, but only where we can attribute the reset to
// the host itself. Off-segment it may have come from a middlebox, so the
// default must not report the address as alive.
func TestStagedSweep_RefusalCountsOnlyWhenAttached(t *testing.T) {
	dead := deadPort(t)
	ports := []int{dead}

	attached := stagedSweep(context.Background(), []string{"127.0.0.1"},
		withDefaults(Config{Ports: ports, Attached: true, Timeout: time.Second}))
	if len(attached) != 1 {
		t.Fatalf("attached: hits = %d, want 1 (a refusal proves liveness on-segment)", len(attached))
	}
	if !attached[0].refused {
		t.Error("attached: hit should be marked refused")
	}
	if attached[0].port != 0 {
		t.Errorf("attached: port = %d, want 0 — a refusal means nothing is listening", attached[0].port)
	}

	routed := stagedSweep(context.Background(), []string{"127.0.0.1"},
		withDefaults(Config{Ports: ports, Attached: false, Timeout: time.Second}))
	if len(routed) != 0 {
		t.Errorf("routed: hits = %d, want 0 — a reset off-segment may be a middlebox", len(routed))
	}
}

// Results must reach the caller as they are found, not in one batch at the end.
func TestRun_OnResultStreamsHosts(t *testing.T) {
	open := listenerOn(t)

	var mu sync.Mutex
	var streamed []Result
	got := Run(context.Background(), []string{"127.0.0.1"}, Config{
		Ports:   []int{open},
		Timeout: time.Second,
		ARP:     func(context.Context) map[string]string { return nil },
		OnResult: func(r Result) {
			mu.Lock()
			streamed = append(streamed, r)
			mu.Unlock()
		},
	})

	mu.Lock()
	defer mu.Unlock()
	if len(streamed) != len(got) {
		t.Fatalf("streamed %d results, returned %d — they must agree", len(streamed), len(got))
	}
	if len(streamed) != 1 || streamed[0].IP != "127.0.0.1" {
		t.Fatalf("streamed = %+v, want one result for 127.0.0.1", streamed)
	}
	if !streamed[0].ViaTCP {
		t.Error("streamed result should be marked ViaTCP")
	}
}

// An ARP-known host must not be streamed twice when the TCP sweep also finds it.
func TestRun_OnResultDoesNotDuplicateARPHosts(t *testing.T) {
	open := listenerOn(t)

	var mu sync.Mutex
	seen := map[string]int{}
	Run(context.Background(), []string{"127.0.0.1"}, Config{
		Ports:   []int{open},
		Timeout: time.Second,
		ARP: func(context.Context) map[string]string {
			return map[string]string{"127.0.0.1": "aa:bb:cc:dd:ee:ff"}
		},
		OnResult: func(r Result) {
			mu.Lock()
			seen[r.IP]++
			mu.Unlock()
		},
	})

	mu.Lock()
	defer mu.Unlock()
	if seen["127.0.0.1"] != 1 {
		t.Errorf("streamed 127.0.0.1 %d times, want exactly 1", seen["127.0.0.1"])
	}
}

// deadPort returns a port on loopback that nothing is listening on, by opening
// a listener and immediately closing it.
func deadPort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close()
	return port
}

// Guard against the port number ever being formatted differently than the
// dialer expects; a mismatch here would silently probe the wrong address.
func TestStagedSweep_DialsTheRequestedPort(t *testing.T) {
	open := listenerOn(t)
	hits := stagedSweep(context.Background(), []string{"127.0.0.1"},
		withDefaults(Config{Ports: []int{open}, Timeout: time.Second}))
	if len(hits) != 1 {
		t.Fatalf("hits = %d, want 1", len(hits))
	}
	if got := strconv.Itoa(hits[0].port); got != strconv.Itoa(open) {
		t.Errorf("port = %s, want %s", got, strconv.Itoa(open))
	}
}
