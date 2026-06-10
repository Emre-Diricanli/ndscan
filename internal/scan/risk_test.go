package scan

import "testing"

func TestClassifyPort_ByNumber(t *testing.T) {
	cases := []struct {
		port int
		svc  string
		want Severity
	}{
		{23, "telnet", SevHigh},
		{21, "ftp", SevHigh},
		{2049, "nfs", SevHigh},
		{445, "microsoft-ds", SevWarn},
		{3389, "ms-wbt-server", SevWarn},
		{3306, "mysql", SevWarn},
		{22, "ssh", SevInfo},
		{8080, "http-proxy", SevInfo},
		{80, "http", SevNone},
		{443, "https", SevNone},
		{49152, "unknown", SevNone},
	}
	for _, c := range cases {
		got := ClassifyPort(c.port, c.svc)
		if got.Severity != c.want {
			t.Errorf("ClassifyPort(%d,%q) severity = %v, want %v", c.port, c.svc, got.Severity, c.want)
		}
		if c.want != SevNone && got.Reason == "" {
			t.Errorf("ClassifyPort(%d,%q) returned empty reason for sev %v", c.port, c.svc, c.want)
		}
	}
}

func TestClassifyPort_ByServiceOnNonStandardPort(t *testing.T) {
	// Telnet on a non-standard port should still be flagged via service name.
	got := ClassifyPort(48023, "telnet")
	if got.Severity != SevHigh {
		t.Errorf("non-standard telnet severity = %v, want high", got.Severity)
	}
	// Case-insensitive + trimmed service matching.
	got = ClassifyPort(49000, "  MySQL  ")
	if got.Severity != SevWarn {
		t.Errorf("messy mysql service severity = %v, want warn", got.Severity)
	}
}

func TestSeverityString(t *testing.T) {
	cases := map[Severity]string{
		SevHigh: "high", SevWarn: "warn", SevInfo: "info", SevNone: "",
	}
	for sev, want := range cases {
		if got := sev.String(); got != want {
			t.Errorf("Severity(%d).String() = %q, want %q", sev, got, want)
		}
	}
}
