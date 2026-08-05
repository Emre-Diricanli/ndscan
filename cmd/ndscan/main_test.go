package main

import (
	"os"
	"strings"
	"testing"
)

func TestWantsPrivilegedScan(t *testing.T) {
	cases := []struct {
		name string
		args []string
		want bool
	}{
		{"bare TUI", nil, false},
		{"tui subcommand", []string{"tui"}, false},
		{"version flag", []string{"--version"}, false},
		{"version short", []string{"-v"}, false},
		{"help flag", []string{"--help"}, false},
		{"help subcommand", []string{"help"}, false},
		{"scan help does not elevate", []string{"scan", "--help"}, false},
		{"plain scan elevates", []string{"scan", "192.168.1.0/24"}, true},
		// --fast is native ARP+TCP discovery: unprivileged by design, so it must
		// never trigger a sudo relaunch.
		{"fast scan stays unprivileged", []string{"scan", "192.168.1.0/24", "--fast"}, false},
		{"fast flag before target", []string{"scan", "--fast", "10.0.0.0/24"}, false},
		{"scan with flags before target", []string{"scan", "-tb", "10.0.0.0/24"}, true},
		{"unknown subcommand does not elevate", []string{"completion"}, false},
	}
	for _, c := range cases {
		if got := wantsPrivilegedScan(c.args); got != c.want {
			t.Errorf("%s: wantsPrivilegedScan(%v) = %v, want %v", c.name, c.args, got, c.want)
		}
	}
}

func TestLooksLikeSSHTarget(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		{"user@203.0.113.10", true},
		{"admin@scanner.internal", true},
		{"192.168.1.0/24", false},
		{"192.168.1.5", false},
		// A CIDR can't be an SSH target even with an '@' — the '/' rules it out.
		{"user@host/24", false},
		{"", false},
	}
	for _, c := range cases {
		if got := looksLikeSSHTarget(c.in); got != c.want {
			t.Errorf("looksLikeSSHTarget(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}

func TestNormalizeArgs_RewritesViewAliases(t *testing.T) {
	orig := os.Args
	t.Cleanup(func() { os.Args = orig })

	os.Args = []string{"ndscan", "scan", "-tb", "192.168.1.0/24", "-tr", "--preset", "quick"}
	normalizeArgs()

	want := []string{"ndscan", "scan", "--tb", "192.168.1.0/24", "--tr", "--preset", "quick"}
	if len(os.Args) != len(want) {
		t.Fatalf("len = %d (%v), want %d", len(os.Args), os.Args, len(want))
	}
	for i := range want {
		if os.Args[i] != want[i] {
			t.Fatalf("args = %v, want %v", os.Args, want)
		}
	}
}

func TestNormalizeArgs_LeavesOtherArgsAlone(t *testing.T) {
	orig := os.Args
	t.Cleanup(func() { os.Args = orig })

	// A bare "ndscan" (TUI launch) and unrelated flags must pass through.
	os.Args = []string{"ndscan"}
	normalizeArgs()
	if len(os.Args) != 1 || os.Args[0] != "ndscan" {
		t.Errorf("bare invocation altered: %v", os.Args)
	}

	os.Args = []string{"ndscan", "scan", "-p", "22,80", "--tbx"}
	normalizeArgs()
	for _, a := range os.Args {
		if a == "--tb" || a == "--tr" {
			t.Errorf("unexpected alias rewrite in %v", os.Args)
		}
	}
}

func TestValidatePreset(t *testing.T) {
	for _, ok := range []string{"quick", "smart", "default", "udp", "deep"} {
		if err := validatePreset(ok); err != nil {
			t.Errorf("validatePreset(%q) = %v, want nil", ok, err)
		}
	}
	for _, bad := range []string{"quikc", "QUICK", "", "fast"} {
		err := validatePreset(bad)
		if err == nil {
			t.Errorf("validatePreset(%q) = nil, want an error", bad)
			continue
		}
		// The message must list the valid choices so the fix is obvious.
		if !strings.Contains(err.Error(), "quick") {
			t.Errorf("validatePreset(%q) error %q should list valid presets", bad, err)
		}
	}
}

func TestValidateView(t *testing.T) {
	for _, ok := range []string{"table", "tree"} {
		if err := validateView(ok); err != nil {
			t.Errorf("validateView(%q) = %v, want nil", ok, err)
		}
	}
	for _, bad := range []string{"treeeee", "TABLE", "", "json"} {
		if err := validateView(bad); err == nil {
			t.Errorf("validateView(%q) = nil, want an error", bad)
		}
	}
}

func TestValidatePositive(t *testing.T) {
	if err := validatePositive("concurrency", 1); err != nil {
		t.Errorf("validatePositive(1) = %v, want nil", err)
	}
	if err := validatePositive("concurrency", 64); err != nil {
		t.Errorf("validatePositive(64) = %v, want nil", err)
	}
	for _, bad := range []int{0, -1, -64} {
		err := validatePositive("concurrency", bad)
		if err == nil {
			t.Errorf("validatePositive(%d) = nil, want an error", bad)
			continue
		}
		if !strings.Contains(err.Error(), "concurrency") {
			t.Errorf("error %q should name the flag", err)
		}
	}
}

func TestReportFormat(t *testing.T) {
	cases := []struct {
		path    string
		want    string
		wantErr bool
	}{
		{"out.html", "html", false},
		{"OUT.HTML", "html", false},
		{"report.md", "md", false},
		{"report.MD", "md", false},
		{"/tmp/a/b/findings.md", "md", false},
		// An unrecognized or missing extension must be rejected rather than
		// silently written as Markdown.
		{"noext", "", true},
		{"report.txt", "", true},
		{"report.json", "", true},
	}
	for _, c := range cases {
		got, err := reportFormat(c.path)
		if c.wantErr {
			if err == nil {
				t.Errorf("reportFormat(%q) = %q, want an error", c.path, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("reportFormat(%q) = %v, want %q", c.path, err, c.want)
			continue
		}
		if got != c.want {
			t.Errorf("reportFormat(%q) = %q, want %q", c.path, got, c.want)
		}
	}
}
