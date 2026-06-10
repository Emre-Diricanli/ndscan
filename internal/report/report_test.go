package report

import (
	"strings"
	"testing"

	"github.com/Emre-Diricanli/ndscan/internal/ui"
)

func sampleReport() Report {
	return Report{
		Targets:   "192.168.86.0/24",
		Preset:    "deep",
		Generated: "2026-06-10 14:22:00",
		Rows: []ui.Row{
			{
				IP: "192.168.86.1", Host: "router", Vendor: "Google", Up: true,
			},
			{
				IP: "192.168.86.31", Up: true, OS: "Linux 5.X", OSAccuracy: 92,
				PortDetails: []ui.PortInfo{
					{Port: 23, Proto: "tcp", Service: "telnet", Severity: "high", Risk: "Telnet — cleartext"},
				},
			},
			{
				IP: "192.168.86.45", Host: "printer", Up: true,
				PortDetails: []ui.PortInfo{
					{Port: 8443, Proto: "tcp", Service: "http", Product: "nginx", Version: "1.25",
						TLS: true, Cert: "Acme — exp 2027-01-02", Severity: "info", Risk: "admin panel"},
				},
			},
		},
	}
}

func TestMarkdown_StructureAndFindings(t *testing.T) {
	md := sampleReport().Markdown()

	for _, want := range []string{
		"# Network scan — 2026-06-10 14:22:00",
		"`192.168.86.0/24`",
		"## ⚠ Exposure",
		"1 high · 0 warn",
		"telnet", // the flagged service
		"## Hosts",
		"Linux 5.X (92%)",
		"## Service detail",
		"🔒",                     // TLS marker
		"Acme — exp 2027-01-02", // cert
	} {
		if !strings.Contains(md, want) {
			t.Errorf("markdown missing %q", want)
		}
	}

	// High finding must sort above the info one — telnet row appears in the
	// exposure table; the info port (8443) must not (only warn/high listed).
	exposure := md[strings.Index(md, "## ⚠ Exposure"):strings.Index(md, "## Hosts")]
	if strings.Contains(exposure, "8443") {
		t.Error("info-severity port should not appear in the exposure section")
	}
}

func TestMarkdown_NoFindings(t *testing.T) {
	r := Report{Generated: "now", Rows: []ui.Row{{IP: "10.0.0.1", Up: true}}}
	md := r.Markdown()
	if !strings.Contains(md, "## ✓ Exposure") || !strings.Contains(md, "No risky ports") {
		t.Error("clean scan should render the no-exposure section")
	}
}

func TestHTML_EscapesAndSelfContained(t *testing.T) {
	r := Report{
		Generated: "now",
		Rows: []ui.Row{{
			IP: "10.0.0.1", Host: `a<script>"x"`, Up: true,
			PortDetails: []ui.PortInfo{{Port: 80, Proto: "tcp", Service: "http",
				HTTPTitle: `<b>pwn</b>`, Severity: "info"}},
		}},
	}
	h := r.HTML()
	if !strings.HasPrefix(h, "<!doctype html>") || !strings.Contains(h, "<style>") {
		t.Error("HTML should be a self-contained document with inline CSS")
	}
	// User-controlled strings must be escaped, not injected raw.
	if strings.Contains(h, "<script>") || strings.Contains(h, "<b>pwn</b>") {
		t.Error("HTML must escape host/title values")
	}
	if !strings.Contains(h, "&lt;script&gt;") {
		t.Error("expected escaped host value")
	}
}
