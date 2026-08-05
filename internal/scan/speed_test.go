package scan

import "testing"

import (
	"context"
	"errors"
	"strings"
	"sync"
)

func TestEffectiveConcurrency(t *testing.T) {
	cases := []struct {
		requested, hosts, want int
	}{
		{64, 3, 3},      // never more workers than hosts
		{64, 200, 64},   // honor the requested cap on big ranges
		{1, 50, 1},      // user can throttle low
		{0, 10, 1},      // clamp non-positive to at least 1
		{32, 0, 1},      // no hosts -> 1 (caller guards len==0 anyway)
		{100, 100, 100}, // equal
	}
	for _, c := range cases {
		if got := effectiveConcurrency(c.requested, c.hosts); got != c.want {
			t.Errorf("effectiveConcurrency(%d,%d) = %d, want %d", c.requested, c.hosts, got, c.want)
		}
	}
}

type fallbackRunner struct {
	mu    sync.Mutex
	calls [][]string
}

func (r *fallbackRunner) Run(_ context.Context, _ string, args ...string) ([]byte, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls = append(r.calls, append([]string(nil), args...))
	if len(r.calls) == 1 {
		return nil, errors.New("dnet: failed to open device en0: Couldn't open a raw socket. Operation not permitted")
	}
	return []byte("<nmaprun></nmaprun>"), nil
}

func TestScanHostsFallsBackFromSYNWhenRawSocketsDenied(t *testing.T) {
	runner := &fallbackRunner{}
	results, err := ScanHosts(context.Background(), []string{"192.0.2.1"}, Config{
		Preset: "quick", UseSYN: true, Concurrency: 1,
	}, runner)
	if err != nil || len(results) != 1 || results[0].Err != nil {
		t.Fatalf("fallback result=%+v err=%v", results, err)
	}
	if !results[0].Fallback {
		t.Fatal("successful TCP retry should be marked as a fallback")
	}
	if len(runner.calls) != 2 {
		t.Fatalf("calls=%d, want SYN attempt plus connect fallback", len(runner.calls))
	}
	joinedFirst := strings.Join(runner.calls[0], " ")
	joinedSecond := strings.Join(runner.calls[1], " ")
	if !strings.Contains(joinedFirst, "-sS") || !strings.Contains(joinedSecond, "-sT") {
		t.Fatalf("first=%q second=%q", joinedFirst, joinedSecond)
	}
}

func TestHostsUpResults(t *testing.T) {
	ips := []string{"192.168.1.10", "192.168.1.20"}
	res := HostsUpResults(ips)
	if len(res) != 2 {
		t.Fatalf("want 2 results, got %d", len(res))
	}
	// each must parse as an up host with the right IP and no open ports
	for i, r := range res {
		if r.IP != ips[i] {
			t.Errorf("result %d IP = %q, want %q", i, r.IP, ips[i])
		}
		nr, err := ParseOne(r.XMLBytes)
		if err != nil {
			t.Fatalf("synthetic XML didn't parse: %v", err)
		}
		if len(nr.Hosts) != 1 || nr.Hosts[0].Status.State != "up" {
			t.Errorf("result %d not parsed as one up host: %+v", i, nr.Hosts)
		}
		if len(nr.Hosts[0].Ports.List) != 0 {
			t.Errorf("result %d should have no ports", i)
		}
		var ip string
		for _, a := range nr.Hosts[0].Addresses {
			if a.AddrType == "ipv4" {
				ip = a.Addr
			}
		}
		if ip != ips[i] {
			t.Errorf("result %d parsed IP = %q, want %q", i, ip, ips[i])
		}
	}
}

type batchRunner struct {
	mu    sync.Mutex
	calls int
}

func (r *batchRunner) Run(context.Context, string, ...string) ([]byte, error) {
	r.mu.Lock()
	r.calls++
	r.mu.Unlock()
	return []byte("<nmaprun></nmaprun>"), nil
}

func TestScanHostsBatchesAndDiscards(t *testing.T) {
	live := make([]string, 40)
	for i := range live {
		live[i] = "192.0.2.1"
	}
	runner := &batchRunner{}
	callbacks, progress := 0, 0
	var mu sync.Mutex
	got, err := ScanHosts(context.Background(), live, Config{
		Preset: "quick", Concurrency: 32, BatchSize: 16, DiscardResults: true,
		OnResult: func(HostResult) { mu.Lock(); callbacks++; mu.Unlock() },
		Progress: func(done, _ int) { mu.Lock(); progress = done; mu.Unlock() },
	}, runner)
	if err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	defer mu.Unlock()
	if runner.calls != 3 || callbacks != 3 || progress != 40 {
		t.Fatalf("calls=%d callbacks=%d progress=%d, want 3/3/40", runner.calls, callbacks, progress)
	}
	if got != nil {
		t.Fatalf("discard mode retained %d results", len(got))
	}
}
