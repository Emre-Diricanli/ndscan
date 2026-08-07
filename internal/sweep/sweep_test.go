package sweep

import (
	"context"
	"net"
	"strconv"
	"testing"
	"time"
)

func TestExpandTargets_CIDRSkipsNetworkAndBroadcast(t *testing.T) {
	got := expandTargets([]string{"192.168.5.0/30"})
	// /30 => .0 network, .1, .2 hosts, .3 broadcast
	want := []string{"192.168.5.1", "192.168.5.2"}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got %v, want %v", got, want)
		}
	}
}

func TestExpandTargets_SlashTwentyFourHasHostCount(t *testing.T) {
	got := expandTargets([]string{"10.1.2.0/24"})
	if len(got) != 254 {
		t.Errorf("/24 expanded to %d hosts, want 254", len(got))
	}
	for _, bad := range []string{"10.1.2.0", "10.1.2.255"} {
		for _, g := range got {
			if g == bad {
				t.Errorf("%s must be excluded from a /24 expansion", bad)
			}
		}
	}
}

func TestExpandTargets_AcceptsBareAddressAndSlash32(t *testing.T) {
	got := expandTargets([]string{"192.168.1.7", "10.0.0.5/32"})
	if len(got) != 2 {
		t.Fatalf("got %v, want 2 addresses", got)
	}
}

// A range broader than /16 is refused rather than silently truncated.
func TestExpandTargets_RefusesHugeRanges(t *testing.T) {
	if got := expandTargets([]string{"10.0.0.0/8"}); len(got) != 0 {
		t.Errorf("/8 should be refused, got %d addresses", len(got))
	}
	if got := expandTargets([]string{"172.16.0.0/16"}); len(got) == 0 {
		t.Error("/16 should still be allowed")
	}
}

func TestExpandTargets_IgnoresGarbageAndIPv6(t *testing.T) {
	got := expandTargets([]string{"", "not-an-ip", "999.1.1.1", "2001:db8::/64"})
	if len(got) != 0 {
		t.Errorf("garbage should expand to nothing, got %v", got)
	}
}

func TestExpandTargets_Deduplicates(t *testing.T) {
	got := expandTargets([]string{"192.168.9.5", "192.168.9.5", "192.168.9.4/31"})
	seen := map[string]int{}
	for _, g := range got {
		seen[g]++
	}
	for ip, n := range seen {
		if n > 1 {
			t.Errorf("%s appeared %d times", ip, n)
		}
	}
}

// The ARP cache alone must produce hosts, with no probe traffic at all.
func TestRun_ARPOnly(t *testing.T) {
	cfg := Config{
		SkipTCP: true,
		ARP: func(context.Context) map[string]string {
			return map[string]string{
				"192.168.4.10": "aa:bb:cc:dd:ee:01",
				"192.168.4.20": "aa:bb:cc:dd:ee:02",
				"10.0.0.1":     "aa:bb:cc:dd:ee:03", // outside target: must be dropped
			}
		},
	}
	got := Run(context.Background(), []string{"192.168.4.0/24"}, cfg)
	if len(got) != 2 {
		t.Fatalf("got %d hosts, want 2 (out-of-target ARP entries must be dropped): %+v", len(got), got)
	}
	for _, r := range got {
		if !r.ViaARP || r.MAC == "" {
			t.Errorf("ARP-sourced host missing flags/MAC: %+v", r)
		}
		if r.ViaTCP {
			t.Errorf("SkipTCP set but host marked ViaTCP: %+v", r)
		}
	}
	// Results are ordered numerically.
	if got[0].IP != "192.168.4.10" || got[1].IP != "192.168.4.20" {
		t.Errorf("results not in numeric order: %+v", got)
	}
}

// A real listener on loopback must be discovered by the TCP sweep.
func TestRun_TCPFindsRealListener(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()

	_, portStr, _ := net.SplitHostPort(ln.Addr().String())
	port, _ := strconv.Atoi(portStr)

	got := Run(context.Background(), []string{"127.0.0.1"}, Config{
		Ports:   []int{port},
		Timeout: 2 * time.Second,
	})
	if len(got) != 1 {
		t.Fatalf("got %d hosts, want 1: %+v", len(got), got)
	}
	if !got[0].ViaTCP {
		t.Errorf("host should be marked ViaTCP: %+v", got[0])
	}
	if got[0].OpenPort != port {
		t.Errorf("OpenPort = %d, want %d", got[0].OpenPort, port)
	}
	if got[0].RTT <= 0 || got[0].RTT > 2*time.Second {
		t.Errorf("RTT = %v, want a plausible non-zero connect duration", got[0].RTT)
	}
}

// A closed port yields no host — no false positives.
func TestRun_ClosedPortFindsNothing(t *testing.T) {
	// Bind then immediately close, so the port is almost certainly free.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	_, portStr, _ := net.SplitHostPort(ln.Addr().String())
	port, _ := strconv.Atoi(portStr)
	ln.Close()

	got := Run(context.Background(), []string{"127.0.0.1"}, Config{
		Ports:   []int{port},
		Timeout: 250 * time.Millisecond,
	})
	if len(got) != 0 {
		t.Errorf("closed port produced %d hosts, want 0: %+v", len(got), got)
	}
}

// ARP and TCP results for the same host merge into one entry carrying both.
func TestRun_MergesARPAndTCP(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()
	_, portStr, _ := net.SplitHostPort(ln.Addr().String())
	port, _ := strconv.Atoi(portStr)

	got := Run(context.Background(), []string{"127.0.0.1"}, Config{
		Ports:   []int{port},
		Timeout: 2 * time.Second,
		ARP: func(context.Context) map[string]string {
			return map[string]string{"127.0.0.1": "aa:bb:cc:dd:ee:ff"}
		},
	})
	if len(got) != 1 {
		t.Fatalf("got %d hosts, want 1 merged entry: %+v", len(got), got)
	}
	r := got[0]
	if !r.ViaARP || !r.ViaTCP {
		t.Errorf("merged host should carry both sources: %+v", r)
	}
	if r.MAC != "aa:bb:cc:dd:ee:ff" {
		t.Errorf("MAC lost in merge: %+v", r)
	}
}

// Cancelling the context must stop the sweep promptly rather than running to
// completion across the whole range.
func TestRun_ContextCancelStopsEarly(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // already cancelled

	start := time.Now()
	got := Run(ctx, []string{"192.0.2.0/24"}, Config{ // TEST-NET-1, routes nowhere
		Timeout:     5 * time.Second,
		Concurrency: 64,
	})
	if elapsed := time.Since(start); elapsed > 3*time.Second {
		t.Errorf("cancelled sweep took %s, should abort quickly", elapsed)
	}
	if len(got) != 0 {
		t.Errorf("cancelled sweep returned %d hosts", len(got))
	}
}

func TestWithDefaults(t *testing.T) {
	c := withDefaults(Config{})
	if len(c.Ports) == 0 || c.Timeout <= 0 || c.Concurrency <= 0 {
		t.Errorf("zero Config not filled in: %+v", c)
	}
	// Concurrency is capped defensively.
	if c := withDefaults(Config{Concurrency: 999999}); c.Concurrency != maxConcurrency {
		t.Errorf("Concurrency = %d, want cap %d", c.Concurrency, maxConcurrency)
	}
}

func TestIPsAndMACs(t *testing.T) {
	rs := []Result{
		{IP: "10.0.0.1", MAC: "aa:bb:cc:dd:ee:01"},
		{IP: "10.0.0.2"},
	}
	if ips := IPs(rs); len(ips) != 2 || ips[0] != "10.0.0.1" {
		t.Errorf("IPs = %v", ips)
	}
	macs := MACs(rs)
	if len(macs) != 1 || macs["10.0.0.1"] != "aa:bb:cc:dd:ee:01" {
		t.Errorf("MACs = %v, want only the host that had one", macs)
	}
}

func TestProgressIsReported(t *testing.T) {
	var mu = make(chan struct{}, 1)
	mu <- struct{}{}
	maxDone, seenTotal := 0, 0
	got := Run(context.Background(), []string{"127.0.0.1"}, Config{
		Ports:   []int{1, 2, 3},
		Timeout: 100 * time.Millisecond,
		Progress: func(done, total int) {
			<-mu
			if done > maxDone {
				maxDone = done
			}
			seenTotal = total
			mu <- struct{}{}
		},
	})
	_ = got
	if seenTotal != 3 {
		t.Errorf("progress total = %d, want 3", seenTotal)
	}
	if maxDone == 0 {
		t.Error("progress never reported")
	}
}
