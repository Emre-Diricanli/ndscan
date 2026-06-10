package report

import (
	"os"
	"testing"

	"github.com/Emre-Diricanli/ndscan/internal/ui"
)

func TestWriteDemo(t *testing.T) {
	if os.Getenv("NDSCAN_REPORT_DEMO") != "1" {
		t.Skip("set NDSCAN_REPORT_DEMO=1 to write demo report files")
	}
	r := Report{
		Targets: "192.168.86.0/24", Preset: "deep", Generated: "2026-06-10 14:22:00",
		Rows: []ui.Row{
			{IP: "192.168.86.1", Host: "router", Vendor: "Google", Up: true, RTT: "3.1ms"},
			{IP: "192.168.86.31", Up: true, OS: "Linux 5.X", OSAccuracy: 92, RTT: "5.0ms",
				PortDetails: []ui.PortInfo{{Port: 23, Proto: "tcp", Service: "telnet", Severity: "high", Risk: "Telnet — cleartext, no encryption"}}},
			{IP: "192.168.86.20", Host: "nas", Vendor: "Synology", Up: true, RTT: "1.2ms",
				PortDetails: []ui.PortInfo{{Port: 445, Proto: "tcp", Service: "microsoft-ds", Severity: "warn", Risk: "SMB — Windows file sharing exposed"}}},
			{IP: "192.168.86.45", Host: "printer", Vendor: "HP", Up: true, OS: "HP embedded", OSAccuracy: 94, RTT: "8.0ms",
				PortDetails: []ui.PortInfo{{Port: 8443, Proto: "tcp", Service: "http", Product: "nginx", Version: "1.25",
					ExtraInfo: "Ubuntu", CPE: "cpe:/a:igor_sysoev:nginx:1.25", TLS: true, HTTPTitle: "HP LaserJet",
					Cert: "HP Inc — exp 2027-03-01", Severity: "info", Risk: "HTTPS-alt — admin panel"}}},
		},
	}
	if err := os.WriteFile("/tmp/scan.md", []byte(r.Markdown()), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile("/tmp/scan.html", []byte(r.HTML()), 0o644); err != nil {
		t.Fatal(err)
	}
}
