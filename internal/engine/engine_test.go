package engine

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Emre-Diricanli/ndscan/internal/scan"
)

// fakeRunner answers nmap and arp invocations from a canned script, so a test
// can drive a whole scan without touching the network.
//
// Discovery, the ARP cache, and the port scan are told apart by their flags:
// `-sn -oG -` is greppable host discovery, `-a -n` is the ARP cache, and
// anything else is a port scan returning XML.
type fakeRunner struct {
	mu    sync.Mutex
	up    []string // hosts discovery should report as up
	ports []byte   // XML the port scan returns
	err   error
	calls [][]string
}

func (r *fakeRunner) Run(_ context.Context, bin string, args ...string) ([]byte, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls = append(r.calls, append([]string(nil), args...))
	if r.err != nil {
		return nil, r.err
	}
	if bin == "arp" {
		return nil, nil // empty cache: the scan must not depend on one
	}
	for _, a := range args {
		if a == "-sn" {
			return grepUp(r.up...), nil
		}
	}
	return r.ports, nil
}

// grepUp renders nmap's greppable "Status: Up" lines, which is what
// HostDiscovery parses.
func grepUp(ips ...string) []byte {
	var b strings.Builder
	for _, ip := range ips {
		b.WriteString("Host: " + ip + " ()\tStatus: Up\n")
	}
	return []byte(b.String())
}

func hostXML(ips ...string) []byte {
	var b strings.Builder
	b.WriteString("<nmaprun>")
	for _, ip := range ips {
		b.WriteString(`<host><status state="up"/><address addr="` + ip + `" addrtype="ipv4"/>`)
		b.WriteString(`<ports><port protocol="tcp" portid="22"><state state="open"/>`)
		b.WriteString(`<service name="ssh"/></port></ports></host>`)
	}
	b.WriteString("</nmaprun>")
	return []byte(b.String())
}

func testEngine(r scan.Runner) *Engine {
	return &Engine{NewRunner: func(string) scan.Runner { return r }}
}

// A plan that avoids the native sweep, so the fake runner sees every call.
func nmapPlan(targets ...string) Plan {
	return Plan{
		Targets:     targets,
		Preset:      "quick",
		Concurrency: 4,
		HostTimeout: time.Second,
	}
}

func TestRunCompletesAndReportsRows(t *testing.T) {
	r := &fakeRunner{up: []string{"192.0.2.1"}, ports: hostXML("192.0.2.1")}
	out := testEngine(r).Run(context.Background(), nmapPlan("192.0.2.1"), nil)

	if out.Status != StatusComplete {
		t.Errorf("status = %v, want complete (err: %v)", out.Status, out.Err)
	}
	if len(out.Rows) != 1 || out.Rows[0].IP != "192.0.2.1" {
		t.Errorf("rows = %+v", out.Rows)
	}
	if !out.Comparable() {
		t.Error("a clean scan with results should be comparable")
	}
}

// The whole reason Outcome exists: a cancelled run must be distinguishable from
// one that looked and found nothing, because only one of them may become the
// baseline for future change detection.
func TestCancelledRunIsNotComparable(t *testing.T) {
	r := &fakeRunner{up: []string{"192.0.2.1"}, ports: hostXML("192.0.2.1")}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	out := testEngine(r).Run(ctx, nmapPlan("192.0.2.1"), nil)
	if out.Status != StatusCancelled {
		t.Errorf("status = %v, want cancelled", out.Status)
	}
	if out.Comparable() {
		t.Error("a cancelled run must never become the baseline")
	}
}

// Finding nothing is a complete answer, but not one worth saving: zero hosts is
// far more often a dropped VPN than an empty network.
func TestEmptyResultIsCompleteButNotComparable(t *testing.T) {
	r := &fakeRunner{ports: []byte("<nmaprun></nmaprun>")}
	out := testEngine(r).Run(context.Background(), nmapPlan("192.0.2.0/30"), nil)

	if out.Status != StatusComplete {
		t.Errorf("status = %v, want complete", out.Status)
	}
	if out.Comparable() {
		t.Error("an empty result must not overwrite a good baseline")
	}
}

func TestDiscoveryFailureReportsFailed(t *testing.T) {
	r := &fakeRunner{err: errors.New("nmap exploded")}
	out := testEngine(r).Run(context.Background(), nmapPlan("192.0.2.1"), nil)

	if out.Status != StatusFailed {
		t.Errorf("status = %v, want failed", out.Status)
	}
	if out.Err == nil {
		t.Error("a failed run must carry its error")
	}
	if out.Comparable() {
		t.Error("a failed run must not become the baseline")
	}
}

// Events are what let a front end draw a host before the slowest address in the
// scan has finished timing out.
func TestRunEmitsPhasesAndRows(t *testing.T) {
	r := &fakeRunner{up: []string{"192.0.2.1"}, ports: hostXML("192.0.2.1")}

	var mu sync.Mutex
	var phases []Phase
	var rowEvents int
	emit := Emit(func(e Event) {
		mu.Lock()
		defer mu.Unlock()
		switch e.Kind {
		case EventPhase:
			phases = append(phases, e.Phase)
		case EventRows:
			rowEvents++
		}
	})

	out := testEngine(r).Run(context.Background(), nmapPlan("192.0.2.1"), emit)
	if out.Status != StatusComplete {
		t.Fatalf("status = %v", out.Status)
	}

	mu.Lock()
	defer mu.Unlock()
	var sawDiscover, sawScan bool
	for _, p := range phases {
		switch p {
		case PhaseDiscover:
			sawDiscover = true
		case PhaseScan:
			sawScan = true
		}
	}
	if !sawDiscover || !sawScan {
		t.Errorf("phases = %v, want both discover and scan", phases)
	}
	if rowEvents == 0 {
		t.Error("rows should stream as hosts complete, not only at the end")
	}
}

// A nil Emit means "I only want the answer" and must not panic.
func TestNilEmitIsSafe(t *testing.T) {
	r := &fakeRunner{up: []string{"192.0.2.1"}, ports: hostXML("192.0.2.1")}
	if out := testEngine(r).Run(context.Background(), nmapPlan("192.0.2.1"), nil); out.Status != StatusComplete {
		t.Errorf("status = %v", out.Status)
	}
}

func TestDiscoverOnlySkipsPortScan(t *testing.T) {
	r := &fakeRunner{up: []string{"192.0.2.1"}}
	p := nmapPlan("192.0.2.1")
	p.DiscoverOnly = true

	out := testEngine(r).Run(context.Background(), p, nil)
	if out.Status != StatusComplete {
		t.Fatalf("status = %v, want complete", out.Status)
	}
	if len(out.Rows) != 1 {
		t.Fatalf("discover-only should still produce rows: %+v", out.Rows)
	}
	if len(out.Rows[0].Ports) != 0 {
		t.Errorf("discover-only must not report ports: %+v", out.Rows[0].Ports)
	}
}

// The scan key must separate runs that could not have found the same things.
func TestScanKeyCarriesActualDiscoveryMode(t *testing.T) {
	p := nmapPlan("192.0.2.0/24")
	p.Ports = "22"

	nmapRun := Outcome{Fast: false}
	fastRun := Outcome{Fast: true}
	if reflect.DeepEqual(nmapRun.ScanKey(p), fastRun.ScanKey(p)) {
		t.Error("a fast sweep and an nmap scan must not share a history key")
	}
	// The key reflects what actually ran, not what the plan asked for: native
	// discovery is unavailable over SSH, so Plan.Fast is only a preference.
	p.Fast = true
	if got := nmapRun.ScanKey(p); got.Fast {
		t.Error("ScanKey must use the outcome's mode, not the plan's request")
	}
}

func TestStatusString(t *testing.T) {
	cases := map[Status]string{
		StatusComplete:  "complete",
		StatusPartial:   "partial",
		StatusCancelled: "cancelled",
		StatusFailed:    "failed",
	}
	for s, want := range cases {
		if got := s.String(); got != want {
			t.Errorf("Status(%d).String() = %q, want %q", int(s), got, want)
		}
	}
}

// Hostname enrichment revises rows the front end has already been given. If it
// announced them as arrivals, a front end that appends would show every host
// twice — so the two must be distinguishable from the event alone.
func TestEnrichmentReportsUpdatesNotArrivals(t *testing.T) {
	r := &fakeRunner{up: []string{"192.0.2.1"}, ports: hostXML("192.0.2.1")}
	p := nmapPlan("192.0.2.1")
	p.Hostnames = true

	var mu sync.Mutex
	var arrivals, updates int
	emit := Emit(func(e Event) {
		mu.Lock()
		defer mu.Unlock()
		switch e.Kind {
		case EventRows:
			arrivals += len(e.Rows)
		case EventRowsUpdated:
			updates += len(e.Rows)
		}
	})

	out := testEngine(r).Run(context.Background(), p, emit)
	if out.Status != StatusComplete {
		t.Fatalf("status = %v", out.Status)
	}

	mu.Lock()
	defer mu.Unlock()
	// One host scanned means exactly one arrival, however many times its row is
	// later revised.
	if arrivals != 1 {
		t.Errorf("arrivals = %d, want 1 (enrichment must not re-announce rows)", arrivals)
	}
	if updates == 0 {
		t.Error("enrichment should report its revision so front ends can refresh")
	}
}
