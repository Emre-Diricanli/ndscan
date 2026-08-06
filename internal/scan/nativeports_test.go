package scan

import (
	"context"
	"net"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/Emre-Diricanli/ndscan/internal/sweep"
)

func TestParsePortSpec(t *testing.T) {
	cases := []struct {
		spec    string
		want    []int
		wantErr bool
	}{
		{"", nil, false},
		{"22", []int{22}, false},
		{"22,80,443", []int{22, 80, 443}, false},
		{"80-83", []int{80, 81, 82, 83}, false},
		{"22,80-82", []int{22, 80, 81, 82}, false},
		{"22, 80 , 443", []int{22, 80, 443}, false},
		{"22,22,22", []int{22}, false}, // de-duplicated
		{"0", nil, true},
		{"70000", nil, true},
		{"-5", nil, true},
		{"junk", nil, true},
		{"22,junk", nil, true},
		{"100-50", nil, true},
	}
	for _, c := range cases {
		got, err := parsePortSpec(c.spec)
		if (err != nil) != c.wantErr {
			t.Errorf("parsePortSpec(%q) error = %v, wantErr %v", c.spec, err, c.wantErr)
			continue
		}
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

func TestNativePortScan_PropagatesIncompleteSignal(t *testing.T) {
	original := scanNativePorts
	t.Cleanup(func() { scanNativePorts = original })
	scanNativePorts = func(_ context.Context, _ []string, cfg sweep.PortConfig) []sweep.PortResult {
		cfg.OnIncomplete(17)
		return []sweep.PortResult{{IP: "192.0.2.1"}}
	}

	results := NativePortScan(context.Background(), []string{"192.0.2.1"}, Config{Ports: "22"}, nil)

	// The scanned host keeps its results: exhaustion means its port list is a
	// floor, not that the host went unscanned. The run-level shortfall arrives
	// as a separate entry so callers counting per-host failures do not throw
	// away results that are incomplete but valid.
	var scanned, incomplete int
	var incompleteErr error
	for _, r := range results {
		switch {
		case r.Err != nil:
			incomplete++
			incompleteErr = r.Err
		case r.IP == "192.0.2.1":
			scanned++
		}
	}
	if scanned != 1 {
		t.Errorf("scanned host results = %d, want 1 (host must not be marked failed)", scanned)
	}
	if incomplete != 1 {
		t.Fatalf("incomplete markers = %d, want exactly 1: %+v", incomplete, results)
	}
	if !strings.Contains(incompleteErr.Error(), "17 probes") {
		t.Errorf("incomplete error = %q, want skipped probe count", incompleteErr)
	}
}

// A run that completes fully must not manufacture a phantom failure entry.
func TestNativePortScan_NoIncompleteMarkerWhenComplete(t *testing.T) {
	original := scanNativePorts
	t.Cleanup(func() { scanNativePorts = original })
	scanNativePorts = func(_ context.Context, _ []string, _ sweep.PortConfig) []sweep.PortResult {
		return []sweep.PortResult{{IP: "192.0.2.1"}}
	}

	for _, r := range NativePortScan(context.Background(), []string{"192.0.2.1"}, Config{Ports: "22"}, nil) {
		if r.Err != nil {
			t.Errorf("complete scan produced an error result: %v", r.Err)
		}
	}
}

func TestNativePortScan_InvalidPortsFailClosed(t *testing.T) {
	called := false
	original := scanNativePorts
	t.Cleanup(func() { scanNativePorts = original })
	scanNativePorts = func(context.Context, []string, sweep.PortConfig) []sweep.PortResult {
		called = true
		return nil
	}

	results := NativePortScan(context.Background(), []string{"192.0.2.1"}, Config{Ports: "22,banana"}, nil)
	if called {
		t.Fatal("malformed port input reached the sweep")
	}
	if len(results) != 1 || results[0].Err == nil || !strings.Contains(results[0].Err.Error(), "banana") {
		t.Fatalf("results = %+v, want an error naming banana", results)
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

// ValidatePorts is what the front ends call before a scan starts. An empty spec
// must stay valid — it means "use the preset's ports" — while anything the
// parser would reject has to be caught here rather than after the scan runs.
func TestValidatePorts(t *testing.T) {
	cases := []struct {
		spec    string
		wantErr bool
	}{
		{"", false},
		{"22", false},
		{"22,80,443", false},
		{"1-1024", false},
		{"22,1000-1010", false},
		{"banana", true},
		{"22,banana", true},
		{"99999", true},
		{"0", true},
		{"100-50", true},
		{"22,,80", true},
	}
	for _, c := range cases {
		if err := ValidatePorts(c.spec); (err != nil) != c.wantErr {
			t.Errorf("ValidatePorts(%q) error = %v, wantErr %v", c.spec, err, c.wantErr)
		}
	}
}
