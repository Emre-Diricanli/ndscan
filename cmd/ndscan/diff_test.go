package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/Emre-Diricanli/ndscan/internal/config"
	"github.com/Emre-Diricanli/ndscan/internal/device"
	"github.com/Emre-Diricanli/ndscan/internal/timeline"
)

// diffTestKey is the history signature every seeded scan in this file uses.
// diffTestOpts must build the same key or the diff sees no baseline.
var diffTestKey = config.ScanKey{Targets: []string{"192.0.2.0/24"}, Preset: "quick"}

func diffTestOpts() diffOptions {
	return diffOptions{targets: []string{"192.0.2.0/24"}, preset: "quick"}
}

func seedHistory(t *testing.T) {
	t.Helper()
	snaps := []config.HostSnapshot{
		{IP: "192.0.2.10", Up: true, Ports: []string{"22/tcp ssh"}},
	}
	if err := config.SaveHistory(diffTestKey, snaps); err != nil {
		t.Fatalf("SaveHistory: %v", err)
	}
}

func seedDevice(t *testing.T, key, name, ip string) {
	t.Helper()
	recs := device.Load()
	recs[key] = device.Record{Key: key, Name: name, Addresses: []string{ip}}
	if err := device.Save(recs); err != nil {
		t.Fatalf("device.Save: %v", err)
	}
}

func seedEvent(t *testing.T, ts time.Time, typ timeline.EventType, key, ip string, port int) {
	t.Helper()
	ev := timeline.Event{Timestamp: ts, Type: typ, DeviceKey: key, IP: ip}
	if port != 0 {
		ev.Port = port
		ev.Protocol = "tcp"
	}
	if err := timeline.Append(ev); err != nil {
		t.Fatalf("timeline.Append: %v", err)
	}
}

func TestRunDiff(t *testing.T) {
	now := time.Now()
	cases := []struct {
		name            string
		seed            func(t *testing.T)
		opts            func() diffOptions
		wantCode        int
		wantContains    []string
		wantNotContains []string
	}{
		{
			name:         "no history says to run a scan first",
			seed:         func(t *testing.T) {},
			wantCode:     diffExitUnchanged,
			wantContains: []string{"no previous scan recorded", "run a scan first"},
		},
		{
			name:            "identical state reports no changes",
			seed:            func(t *testing.T) { seedHistory(t) },
			wantCode:        diffExitUnchanged,
			wantContains:    []string{"no changes"},
			wantNotContains: []string{"appeared", "left"},
		},
		{
			name: "changes render with device labels",
			seed: func(t *testing.T) {
				seedHistory(t)
				seedDevice(t, "ip:192.0.2.42", "kids-tablet", "192.0.2.42")
				// An older batch, then the most recent scan's batch: only the
				// latest may appear in the default view.
				seedEvent(t, now.Add(-2*time.Hour), timeline.EventPortClosed, "ip:192.0.2.10", "192.0.2.10", 22)
				seedEvent(t, now.Add(-1*time.Hour), timeline.EventHostSeen, "ip:192.0.2.42", "192.0.2.42", 0)
				seedEvent(t, now.Add(-1*time.Hour), timeline.EventPortOpened, "ip:192.0.2.10", "192.0.2.10", 8080)
			},
			wantCode:        diffExitChanged,
			wantContains:    []string{"kids-tablet", "192.0.2.42", "appeared", "port opened", "8080"},
			wantNotContains: []string{"port closed"},
		},
		{
			name: "since keeps only events inside the window",
			seed: func(t *testing.T) {
				seedHistory(t)
				seedEvent(t, now.Add(-48*time.Hour), timeline.EventHostSeen, "ip:192.0.2.99", "192.0.2.99", 0)
				seedEvent(t, now.Add(-1*time.Hour), timeline.EventPortOpened, "ip:192.0.2.10", "192.0.2.10", 8080)
			},
			opts: func() diffOptions {
				o := diffTestOpts()
				o.since, o.sinceSet = 24*time.Hour, true
				return o
			},
			wantCode:        diffExitChanged,
			wantContains:    []string{"192.0.2.10", "8080"},
			wantNotContains: []string{"192.0.2.99"},
		},
		{
			name: "since window with no events says so",
			seed: func(t *testing.T) {
				seedHistory(t)
				seedEvent(t, now.Add(-48*time.Hour), timeline.EventHostSeen, "ip:192.0.2.99", "192.0.2.99", 0)
			},
			opts: func() diffOptions {
				o := diffTestOpts()
				o.since, o.sinceSet = 24*time.Hour, true
				return o
			},
			wantCode:        diffExitUnchanged,
			wantContains:    []string{"no changes recorded in the last 24h"},
			wantNotContains: []string{"192.0.2.99"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("NDSCAN_CONFIG_DIR", t.TempDir())
			tc.seed(t)
			o := diffTestOpts()
			if tc.opts != nil {
				o = tc.opts()
			}
			var buf bytes.Buffer
			code, err := runDiff(&buf, o)
			if err != nil {
				t.Fatalf("runDiff: %v", err)
			}
			if code != tc.wantCode {
				t.Errorf("exit code = %d, want %d\noutput:\n%s", code, tc.wantCode, buf.String())
			}
			for _, s := range tc.wantContains {
				if !strings.Contains(buf.String(), s) {
					t.Errorf("output missing %q\noutput:\n%s", s, buf.String())
				}
			}
			for _, s := range tc.wantNotContains {
				if strings.Contains(buf.String(), s) {
					t.Errorf("output unexpectedly contains %q\noutput:\n%s", s, buf.String())
				}
			}
		})
	}
}

// The documented --exit-code contract: runDiff returns the code, RunE exits
// with it. 0 for unchanged, 2 for changed, and never 1 (main reserves 1 for
// real errors).
func TestRunDiffExitCodes(t *testing.T) {
	t.Run("unchanged is 0", func(t *testing.T) {
		t.Setenv("NDSCAN_CONFIG_DIR", t.TempDir())
		seedHistory(t)
		var buf bytes.Buffer
		code, err := runDiff(&buf, diffTestOpts())
		if err != nil {
			t.Fatalf("runDiff: %v", err)
		}
		if code != 0 {
			t.Errorf("code = %d, want 0", code)
		}
	})
	t.Run("changed is 2", func(t *testing.T) {
		t.Setenv("NDSCAN_CONFIG_DIR", t.TempDir())
		seedHistory(t)
		seedEvent(t, time.Now().Add(-time.Hour), timeline.EventHostSeen, "ip:192.0.2.42", "192.0.2.42", 0)
		var buf bytes.Buffer
		code, err := runDiff(&buf, diffTestOpts())
		if err != nil {
			t.Fatalf("runDiff: %v", err)
		}
		if code != 2 {
			t.Errorf("code = %d, want 2", code)
		}
	})
}

func TestRunDiffJSON(t *testing.T) {
	t.Setenv("NDSCAN_CONFIG_DIR", t.TempDir())
	seedHistory(t)
	seedDevice(t, "ip:192.0.2.42", "kids-tablet", "192.0.2.42")
	seedEvent(t, time.Now().Add(-time.Hour), timeline.EventHostSeen, "ip:192.0.2.42", "192.0.2.42", 0)

	o := diffTestOpts()
	o.json = true
	var buf bytes.Buffer
	code, err := runDiff(&buf, o)
	if err != nil {
		t.Fatalf("runDiff: %v", err)
	}
	if code != diffExitChanged {
		t.Errorf("code = %d, want %d", code, diffExitChanged)
	}

	var out diffOutput
	if err := json.Unmarshal(buf.Bytes(), &out); err != nil {
		t.Fatalf("--json output is not JSON: %v\noutput:\n%s", err, buf.String())
	}
	if !out.Changed || !out.Baseline {
		t.Errorf("Changed=%v Baseline=%v, want both true", out.Changed, out.Baseline)
	}
	if out.Mode != "last-scan" {
		t.Errorf("Mode = %q, want %q", out.Mode, "last-scan")
	}
	if len(out.Targets) != 1 || out.Targets[0] != "192.0.2.0/24" {
		t.Errorf("Targets = %v", out.Targets)
	}
	if len(out.Changes) != 1 {
		t.Fatalf("len(Changes) = %d, want 1", len(out.Changes))
	}
	c := out.Changes[0]
	if c.Type != "host_seen" || c.Device != "kids-tablet" || c.IP != "192.0.2.42" {
		t.Errorf("change = %+v", c)
	}
}

// The command itself: flags parse, validation fires, and output goes through
// cobra's configured writer.
func TestDiffCmd(t *testing.T) {
	t.Run("renders through cobra", func(t *testing.T) {
		t.Setenv("NDSCAN_CONFIG_DIR", t.TempDir())
		cmd := newDiffCmd()
		var buf bytes.Buffer
		cmd.SetOut(&buf)
		cmd.SetErr(&buf)
		cmd.SetArgs([]string{"192.0.2.0/24"})
		if err := cmd.Execute(); err != nil {
			t.Fatalf("Execute: %v", err)
		}
		if !strings.Contains(buf.String(), "no previous scan recorded") {
			t.Errorf("output:\n%s", buf.String())
		}
	})
	t.Run("rejects a bad --since", func(t *testing.T) {
		t.Setenv("NDSCAN_CONFIG_DIR", t.TempDir())
		cmd := newDiffCmd()
		var buf bytes.Buffer
		cmd.SetOut(&buf)
		cmd.SetErr(&buf)
		cmd.SetArgs([]string{"192.0.2.0/24", "--since", "yesterday"})
		if err := cmd.Execute(); err == nil {
			t.Fatal("expected invalid --since to fail")
		}
	})
	t.Run("rejects a bad --preset", func(t *testing.T) {
		t.Setenv("NDSCAN_CONFIG_DIR", t.TempDir())
		cmd := newDiffCmd()
		var buf bytes.Buffer
		cmd.SetOut(&buf)
		cmd.SetErr(&buf)
		cmd.SetArgs([]string{"192.0.2.0/24", "--preset", "everything"})
		if err := cmd.Execute(); err == nil {
			t.Fatal("expected invalid --preset to fail")
		}
	})
}
