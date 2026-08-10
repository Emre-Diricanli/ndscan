package ui

import (
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/Emre-Diricanli/ndscan/internal/scan"
	"github.com/Emre-Diricanli/ndscan/internal/vendor"
)

// hostXMLFor builds a minimal nmap XML document for one host with the given
// open ports, so output tests don't need a real scan.
func hostXMLFor(ip string, ports ...int) []byte {
	x := `<nmaprun><host><status state="up"/>` +
		`<address addr="` + ip + `" addrtype="ipv4"/>` +
		`<hostnames><hostname name="h-` + ip + `"/></hostnames><ports>`
	for _, p := range ports {
		svc := "unknown"
		switch p {
		case 22:
			svc = "ssh"
		case 23:
			svc = "telnet"
		case 445:
			svc = "microsoft-ds"
		case 80:
			svc = "http"
		}
		x += `<port protocol="tcp" portid="` + strconv.Itoa(p) + `"><state state="open"/>` +
			`<service name="` + svc + `"/></port>`
	}
	return []byte(x + `</ports></host></nmaprun>`)
}

func TestSummarize_CountsUpHostsAndOpenPorts(t *testing.T) {
	res := []scan.HostResult{
		{IP: "192.168.1.2", XMLBytes: hostXMLFor("192.168.1.2", 22, 80)},
		{IP: "192.168.1.3", XMLBytes: hostXMLFor("192.168.1.3", 445)},
		// A host that errored contributes nothing.
		{IP: "192.168.1.4", Err: os.ErrDeadlineExceeded},
	}
	hostsUp, openPorts := Summarize(res)
	if hostsUp != 2 {
		t.Errorf("hostsUp = %d, want 2", hostsUp)
	}
	if openPorts != 3 {
		t.Errorf("openPorts = %d, want 3", openPorts)
	}
}

func TestRiskCell_ShowsHighestSeverity(t *testing.T) {
	cases := []struct {
		name  string
		ports []PortInfo
		empty bool
	}{
		{"no ports", nil, true},
		{"only unremarkable", []PortInfo{{Port: 12345}}, true},
		{"info only", []PortInfo{{Port: 22, Severity: "info"}}, false},
		{"warn beats info", []PortInfo{{Severity: "info"}, {Severity: "warn"}}, false},
		{"high beats warn", []PortInfo{{Severity: "warn"}, {Severity: "high"}}, false},
	}
	for _, c := range cases {
		got := riskCell(c.ports)
		if c.empty && got != "" {
			t.Errorf("%s: riskCell = %q, want empty", c.name, got)
		}
		if !c.empty && got == "" {
			t.Errorf("%s: riskCell = empty, want a glyph", c.name)
		}
	}
	// The high glyph must differ from the warn glyph, or severity is unreadable.
	high := riskCell([]PortInfo{{Severity: "high"}})
	warn := riskCell([]PortInfo{{Severity: "warn"}})
	if high == warn {
		t.Errorf("high and warn render identically (%q)", high)
	}
}

func TestExtractPortNumber(t *testing.T) {
	cases := map[string]string{
		"22/tcp ssh":             "22",
		"443/tcp https":          "443",
		"8080/tcp http-proxy":    "8080",
		"53/udp domain":          "53",
		"no-leading-digits":      "no-leading-digits",
		"9":                      "9",
		"22/tcp ssh OpenSSH 9.6": "22",
	}
	for in, want := range cases {
		if got := extractPortNumber(in); got != want {
			t.Errorf("extractPortNumber(%q) = %q, want %q", in, got, want)
		}
		// PortNumber is the exported alias and must agree.
		if got := PortNumber(in); got != want {
			t.Errorf("PortNumber(%q) = %q, want %q", in, got, want)
		}
	}
}

// WriteJSONWithMACMap is the --json output path. It must emit the same rows
// BuildRows produces, including MAC backfill from the ARP map.
func TestWriteJSONWithMACMap_MatchesBuildRows(t *testing.T) {
	res := []scan.HostResult{
		{IP: "192.168.1.10", XMLBytes: hostXMLFor("192.168.1.10", 22)},
		{IP: "192.168.1.9", XMLBytes: hostXMLFor("192.168.1.9", 23)},
	}
	macMap := map[string]string{"192.168.1.9": "aa:bb:cc:dd:ee:ff"}
	db := vendor.DB{}

	path := filepath.Join(t.TempDir(), "out.json")
	if err := WriteJSONWithMACMap(res, db, path, true, true, macMap); err != nil {
		t.Fatalf("WriteJSONWithMACMap: %v", err)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	var got []Row
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}
	want := BuildRows(res, db, true, true, macMap)
	if len(got) != len(want) {
		t.Fatalf("json has %d rows, BuildRows has %d", len(got), len(want))
	}
	for i := range want {
		if got[i].IP != want[i].IP {
			t.Errorf("row %d IP = %q, want %q (order must match BuildRows)", i, got[i].IP, want[i].IP)
		}
		if got[i].MAC != want[i].MAC {
			t.Errorf("row %d MAC = %q, want %q", i, got[i].MAC, want[i].MAC)
		}
	}
	// Numeric ordering: .9 must precede .10 in the exported file too.
	if got[0].IP != "192.168.1.9" {
		t.Errorf("first row = %q, want 192.168.1.9 (numeric order)", got[0].IP)
	}
	// The MAC backfill from the ARP map must have been applied.
	if got[0].MAC != "aa:bb:cc:dd:ee:ff" {
		t.Errorf("MAC not backfilled from macMap: %q", got[0].MAC)
	}
}

func TestWriteJSONWithMACMap_OmitsMACWhenNotRequested(t *testing.T) {
	res := []scan.HostResult{{IP: "192.168.1.9", XMLBytes: hostXMLFor("192.168.1.9", 22)}}
	macMap := map[string]string{"192.168.1.9": "aa:bb:cc:dd:ee:ff"}

	path := filepath.Join(t.TempDir(), "out.json")
	if err := WriteJSONWithMACMap(res, nil, path, false, false, macMap); err != nil {
		t.Fatalf("WriteJSONWithMACMap: %v", err)
	}
	var got []Row
	b, _ := os.ReadFile(path)
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatalf("bad json: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("want 1 row, got %d", len(got))
	}
	if got[0].MAC != "" {
		t.Errorf("MAC = %q, want empty when --show-mac is off", got[0].MAC)
	}
}

// captureStderr swaps os.Stderr for a pipe and returns what was written to it.
//
// PrintNextSteps writes there directly rather than to an injectable writer,
// matching PrintSummary above it; the swap is what lets the gating be asserted
// without restructuring both.
func captureStderr(t *testing.T, fn func()) string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	orig := os.Stderr
	os.Stderr = w
	fn()
	os.Stderr = orig
	if err := w.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	b, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	return string(b)
}

// A run that did not become a baseline must not advertise `ndscan diff`.
// Pointing a cancelled or partial scan at diff is advice that cannot be
// followed: the run recorded nothing for diff to read.
func TestPrintNextSteps_SilentWhenNoBaselineRecorded(t *testing.T) {
	got := captureStderr(t, func() {
		PrintNextSteps(false, []string{"192.168.1.0/24"})
	})
	if got != "" {
		t.Fatalf("expected no output for a non-comparable run, got %q", got)
	}
}

// Missing targets would render "ndscan diff " with a dangling command, so the
// hint suppresses itself rather than printing something uncopyable.
func TestPrintNextSteps_SilentWithoutTargets(t *testing.T) {
	got := captureStderr(t, func() { PrintNextSteps(true, nil) })
	if got != "" {
		t.Fatalf("expected no output without targets, got %q", got)
	}
}

// The recorded case names both follow-up commands and echoes the real target,
// so the diff line can be copied as printed.
func TestPrintNextSteps_NamesFollowUpCommandsWithTarget(t *testing.T) {
	got := captureStderr(t, func() {
		PrintNextSteps(true, []string{"192.168.1.0/24"})
	})
	for _, want := range []string{"ndscan diff 192.168.1.0/24", "ndscan devices list", "baseline saved"} {
		if !strings.Contains(got, want) {
			t.Errorf("expected output to mention %q, got %q", want, got)
		}
	}
}
