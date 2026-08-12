package sweep

import (
	"context"
	"net/netip"
	"sync"
	"testing"
	"time"
)

// Every host must be streamed exactly once, and the streamed set must match the
// returned set — callers rely on OnResult *instead of* the return value, so a
// host missing from the stream would be a host missing from the UI.
func TestScanPorts_OnResultStreamsEveryHostOnce(t *testing.T) {
	open := listenerOn(t)

	var mu sync.Mutex
	seen := map[string]int{}
	var streamed []PortResult

	hosts := []string{"127.0.0.1"}
	got := ScanPorts(context.Background(), hosts, PortConfig{
		Ports:   []int{open},
		Timeout: time.Second,
		OnResult: func(r PortResult) {
			mu.Lock()
			seen[r.IP]++
			streamed = append(streamed, r)
			mu.Unlock()
		},
	})

	mu.Lock()
	defer mu.Unlock()
	if len(streamed) != len(got) {
		t.Fatalf("streamed %d, returned %d", len(streamed), len(got))
	}
	for _, h := range hosts {
		if seen[h] != 1 {
			t.Errorf("host %s streamed %d times, want 1", h, seen[h])
		}
	}
	if len(streamed) != 1 || len(streamed[0].Ports) != 1 || streamed[0].Ports[0].Port != open {
		t.Fatalf("streamed = %+v, want the open port %d", streamed, open)
	}
}

// The streamed result must carry the host's full port list, already sorted —
// callers render it directly without waiting for or re-reading the return value.
func TestScanPorts_StreamedResultIsCompleteAndSorted(t *testing.T) {
	a, b := listenerOn(t), listenerOn(t)
	lo, hi := a, b
	if lo > hi {
		lo, hi = hi, lo
	}

	var mu sync.Mutex
	var streamed PortResult
	// Deliberately pass the ports out of order: the result must come back sorted
	// regardless of probe scheduling, which is nondeterministic.
	ScanPorts(context.Background(), []string{"127.0.0.1"}, PortConfig{
		Ports:   []int{hi, lo},
		Timeout: time.Second,
		OnResult: func(r PortResult) {
			mu.Lock()
			streamed = r
			mu.Unlock()
		},
	})

	mu.Lock()
	defer mu.Unlock()
	if len(streamed.Ports) != 2 {
		t.Fatalf("streamed %d ports, want 2 — the stream must carry the complete list", len(streamed.Ports))
	}
	if streamed.Ports[0].Port != lo || streamed.Ports[1].Port != hi {
		t.Errorf("ports = %v, want sorted [%d %d]", streamed.Ports, lo, hi)
	}
}

// A caller retaining a streamed result must not observe it change afterwards.
func TestScanPorts_StreamedResultIsNotAliased(t *testing.T) {
	open := listenerOn(t)

	var mu sync.Mutex
	var held []OpenPort
	got := ScanPorts(context.Background(), []string{"127.0.0.1"}, PortConfig{
		Ports:   []int{open},
		Timeout: time.Second,
		OnResult: func(r PortResult) {
			mu.Lock()
			held = r.Ports
			mu.Unlock()
		},
	})

	// Mutating the returned slice must not reach through to the streamed copy.
	if len(got) > 0 && len(got[0].Ports) > 0 {
		got[0].Ports[0].Port = -1
	}
	mu.Lock()
	defer mu.Unlock()
	if len(held) != 1 || held[0].Port != open {
		t.Errorf("streamed result aliases the returned slice: %v", held)
	}
}

// expandTargets is the memory floor for a large sweep: a /16 materialises every
// address as a string before a single packet goes out. This records that cost so
// a regression toward eager expansion of even larger ranges is visible.
func BenchmarkExpandTargets_Slash16(b *testing.B) {
	for i := 0; i < b.N; i++ {
		addrs := expandTargets([]string{"10.0.0.0/16"})
		if len(addrs) == 0 {
			b.Fatal("no addresses")
		}
	}
}

func BenchmarkExpandTargets_Slash24(b *testing.B) {
	for i := 0; i < b.N; i++ {
		expandTargets([]string{"192.168.1.0/24"})
	}
}

// A quiet /16 is the worst case staging is meant to fix: with no host answering,
// the old scheduler queued addresses x ports probes. This measures the address
// bookkeeping alone (no dialing) to keep the benchmark hermetic.
func BenchmarkStagedSweep_Bookkeeping(b *testing.B) {
	addrs := expandTargets([]string{"10.0.0.0/22"})
	cfg := withDefaults(Config{Ports: DefaultPorts})
	// A cancelled context short-circuits every dial, isolating the scheduling
	// and result-collection cost from network time.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		stagedSweep(ctx, addrs, nil, cfg)
	}
}

// Sanity-check the /16 guard rail rather than the speed: expandTargets refuses
// anything broader, so this is the largest range the engine will ever expand.
func TestExpandTargets_Slash16IsTheCeiling(t *testing.T) {
	got := expandTargets([]string{"10.0.0.0/16"})
	if want := 65534; len(got) != want {
		t.Errorf("/16 expanded to %d addresses, want %d", len(got), want)
	}
	if n := len(expandTargets([]string{"10.0.0.0/15"})); n != 0 {
		t.Errorf("/15 expanded to %d addresses, want 0 (refused as too broad)", n)
	}

	first, err := netip.ParseAddr(got[0])
	if err != nil || first.String() != "10.0.0.1" {
		t.Errorf("first address = %v, want 10.0.0.1 (network address skipped)", got[0])
	}
	if last := got[len(got)-1]; last != "10.0.255.254" {
		t.Errorf("last address = %v, want 10.0.255.254 (broadcast skipped)", last)
	}
}
