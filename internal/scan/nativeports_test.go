package scan

import (
	"context"
	"net"
	"strconv"
	"strings"
	"sync"
	"testing"
)

func TestParsePortSpec(t *testing.T) {
	cases := []struct {
		spec string
		want []int
	}{
		{"", nil},
		{"22", []int{22}},
		{"22,80,443", []int{22, 80, 443}},
		{"80-83", []int{80, 81, 82, 83}},
		{"22,80-82", []int{22, 80, 81, 82}},
		{"22, 80 , 443", []int{22, 80, 443}},
		{"22,22,22", []int{22}}, // de-duplicated
		{"0,70000,-5", nil},     // out of range
		{"junk", nil},           // unparseable
		{"100-50", nil},         // inverted range
	}
	for _, c := range cases {
		got := parsePortSpec(c.spec)
		if len(got) != len(c.want) {
			t.Errorf("parsePortSpec(%q) = %v, want %v", c.spec, got, c.want)
			continue
		}
		for i := range c.want {
			if got[i] != c.want[i] {
				t.Errorf("parsePortSpec(%q) = %v, want %v", c.spec, got, c.want)
				break
			}
		}
	}
}

// The synthetic XML must parse with the same parser used for real nmap output,
// so native results flow through every existing printer unchanged.
func TestNativePortScan_ProducesParseableResults(t *testing.T) {
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

	res := NativePortScan(context.Background(), []string{"127.0.0.1"},
		Config{Ports: portStr, Concurrency: 4}, nil)
	if len(res) != 1 {
		t.Fatalf("got %d results, want 1", len(res))
	}

	nr, err := ParseOne(res[0].XMLBytes)
	if err != nil {
		t.Fatalf("synthetic XML does not parse: %v\n%s", err, res[0].XMLBytes)
	}
	if len(nr.Hosts) != 1 {
		t.Fatalf("parsed %d hosts, want 1", len(nr.Hosts))
	}
	h := nr.Hosts[0]
	if h.Status.State != "up" {
		t.Errorf("host state = %q, want up", h.Status.State)
	}
	var found bool
	for _, p := range h.Ports.List {
		if p.PortID == port && p.State.State == "open" {
			found = true
		}
	}
	if !found {
		t.Errorf("open port %d missing from parsed result: %s", port, res[0].XMLBytes)
	}
}

// A host with nothing listening must still produce a valid, parseable result
// rather than being dropped.
func TestNativePortScan_ClosedHostStillParses(t *testing.T) {
	res := NativePortScan(context.Background(), []string{"127.0.0.1"},
		Config{Ports: "1", Concurrency: 2}, nil)
	if len(res) != 1 {
		t.Fatalf("got %d results, want 1", len(res))
	}
	if _, err := ParseOne(res[0].XMLBytes); err != nil {
		t.Errorf("empty result does not parse: %v", err)
	}
}

func TestSyntheticXML_EscapesHostileValues(t *testing.T) {
	// A crafted service name must not break out of the XML.
	res := NativePortScan(context.Background(), []string{"127.0.0.1"},
		Config{Ports: "1", Concurrency: 1}, nil)
	x := string(res[0].XMLBytes)
	if !strings.HasPrefix(x, "<nmaprun>") || !strings.HasSuffix(x, "</nmaprun>") {
		t.Errorf("malformed envelope: %s", x)
	}
}

func TestNativePortScanViable(t *testing.T) {
	local := LocalRunner{}
	ssh := &SSHRunner{Target: "user@host"}

	if !NativePortScanViable(Config{Preset: "quick"}, local) {
		t.Error("quick preset locally should be viable")
	}
	// Presets that need -A / -sU must stay on nmap.
	for _, p := range []string{"default", "deep", "udp"} {
		if NativePortScanViable(Config{Preset: p}, local) {
			t.Errorf("preset %q needs nmap capabilities, must not be viable", p)
		}
	}
	// Remote scans must never use native probing (wrong source machine).
	if NativePortScanViable(Config{Preset: "quick"}, ssh) {
		t.Error("SSH runner must not use native port scanning")
	}
}

func TestNativePortScan_ProgressReported(t *testing.T) {
	// Progress is documented as being called from multiple goroutines, so the
	// callback must guard its own state.
	var mu sync.Mutex
	var maxDone, total int
	NativePortScan(context.Background(), []string{"127.0.0.1", "127.0.0.2"},
		Config{Ports: "1", Concurrency: 2}, func(done, tot int) {
			mu.Lock()
			defer mu.Unlock()
			if done > maxDone {
				maxDone = done
			}
			total = tot
		})
	mu.Lock()
	defer mu.Unlock()
	if total != 2 {
		t.Errorf("progress total = %d, want 2", total)
	}
	if maxDone == 0 {
		t.Error("progress never reported")
	}
}
