package alert

import (
	"testing"
	"time"

	"github.com/Emre-Diricanli/ndscan/internal/config"
	"github.com/Emre-Diricanli/ndscan/internal/device"
)

var testNow = time.Date(2026, 8, 7, 12, 0, 0, 0, time.UTC)

func stableRecord(key, ip string) device.Record {
	return device.Record{Key: key, Confidence: device.Stable.String(), MAC: key[len("mac:"):], Addresses: []string{ip}}
}

func ephemeralRecord(key, ip string) device.Record {
	return device.Record{Key: key, Confidence: device.Ephemeral.String(), Addresses: []string{ip}}
}

func TestEvaluateNewDevice(t *testing.T) {
	devices := map[string]device.Record{
		"mac:aa:bb:cc:dd:ee:01": stableRecord("mac:aa:bb:cc:dd:ee:01", "192.168.1.50"),
	}

	tests := []struct {
		name    string
		rule    Rule
		keys    []string
		devices map[string]device.Record
		want    int
	}{
		{
			name:    "fires for a new stable device",
			rule:    Rule{Name: "nd", Kind: KindNewDevice, Severity: "info"},
			keys:    []string{"mac:aa:bb:cc:dd:ee:01"},
			devices: devices,
			want:    1,
		},
		{
			name:    "does not fire when nothing is new",
			rule:    Rule{Name: "nd", Kind: KindNewDevice, Severity: "info"},
			keys:    nil,
			devices: devices,
			want:    0,
		},
		{
			name: "stable-only suppresses randomized-MAC churn",
			// A phone that re-randomizes its MAC gets a fresh ephemeral key
			// per visit; scoping to stable keys is what keeps that from
			// alerting every day.
			rule: Rule{Name: "nd", Kind: KindNewDevice, StableOnly: true},
			keys: []string{"ip:192.168.1.77"},
			devices: map[string]device.Record{
				"ip:192.168.1.77": ephemeralRecord("ip:192.168.1.77", "192.168.1.77"),
			},
			want: 0,
		},
		{
			name: "unscoped rule still fires for ephemeral keys",
			rule: Rule{Name: "nd", Kind: KindNewDevice},
			keys: []string{"ip:192.168.1.77"},
			devices: map[string]device.Record{
				"ip:192.168.1.77": ephemeralRecord("ip:192.168.1.77", "192.168.1.77"),
			},
			want: 1,
		},
		{
			name:    "stable-only skips keys with no record",
			rule:    Rule{Name: "nd", Kind: KindNewDevice, StableOnly: true},
			keys:    []string{"mac:aa:bb:cc:dd:ee:99"},
			devices: nil,
			want:    0,
		},
		{
			name:    "ignore list silences a device by key",
			rule:    Rule{Name: "nd", Kind: KindNewDevice, Ignore: []string{"mac:aa:bb:cc:dd:ee:01"}},
			keys:    []string{"mac:aa:bb:cc:dd:ee:01"},
			devices: devices,
			want:    0,
		},
		{
			name:    "ignore list silences a device by IP",
			rule:    Rule{Name: "nd", Kind: KindNewDevice, Ignore: []string{"192.168.1.50"}},
			keys:    []string{"mac:aa:bb:cc:dd:ee:01"},
			devices: devices,
			want:    0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Evaluate([]Rule{tt.rule}, nil, tt.devices, tt.keys, "", "", testNow)
			if len(got) != tt.want {
				t.Fatalf("want %d alerts, got %d: %+v", tt.want, len(got), got)
			}
			for _, a := range got {
				if a.Rule != tt.rule.Name {
					t.Errorf("alert carries wrong rule name: %q", a.Rule)
				}
				if a.Title == "" || a.Body == "" || a.Subject == "" {
					t.Errorf("alert missing human-facing fields: %+v", a)
				}
				if !a.At.Equal(testNow) {
					t.Errorf("alert timestamp not the injected time: %v", a.At)
				}
			}
		})
	}
}

func TestEvaluatePortOpened(t *testing.T) {
	diffWith := func(ip string, ports ...string) map[string]config.HostDiff {
		return map[string]config.HostDiff{ip: {PortsOpened: ports}}
	}

	tests := []struct {
		name         string
		rule         Rule
		diff         map[string]config.HostDiff
		want         int
		wantSeverity string
	}{
		{
			name:         "fires with the port's own risk severity",
			rule:         Rule{Name: "po", Kind: KindPortOpened},
			diff:         diffWith("192.168.1.10", "23"), // Telnet: high
			want:         1,
			wantSeverity: "high",
		},
		{
			name: "does not fire when nothing opened",
			rule: Rule{Name: "po", Kind: KindPortOpened},
			diff: map[string]config.HostDiff{"192.168.1.10": {PortsClosed: []string{"22"}}},
			want: 0,
		},
		{
			name: "port list filters to watched ports",
			rule: Rule{Name: "po", Kind: KindPortOpened, Ports: []int{3389}},
			diff: diffWith("192.168.1.10", "22", "3389"),
			want: 1,
		},
		{
			name: "severity threshold drops unremarkable ports",
			rule: Rule{Name: "po", Kind: KindPortOpened, MinSeverity: "warn"},
			diff: diffWith("192.168.1.10", "80", "22", "445"), // none, info, warn
			want: 1,
		},
		{
			name:         "unclassified port falls back to rule severity",
			rule:         Rule{Name: "po", Kind: KindPortOpened, Severity: "info"},
			diff:         diffWith("192.168.1.10", "12345"),
			want:         1,
			wantSeverity: "info",
		},
		{
			name: "ignored host stays silent",
			rule: Rule{Name: "po", Kind: KindPortOpened, Ignore: []string{"192.168.1.10"}},
			diff: diffWith("192.168.1.10", "23"),
			want: 0,
		},
		{
			name: "gone host's ports are not openings",
			rule: Rule{Name: "po", Kind: KindPortOpened},
			diff: map[string]config.HostDiff{"192.168.1.10": {Gone: true, PortsOpened: []string{"23"}}},
			want: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Evaluate([]Rule{tt.rule}, tt.diff, nil, nil, "", "", testNow)
			if len(got) != tt.want {
				t.Fatalf("want %d alerts, got %d: %+v", tt.want, len(got), got)
			}
			if tt.wantSeverity != "" && got[0].Severity != tt.wantSeverity {
				t.Errorf("want severity %q, got %q", tt.wantSeverity, got[0].Severity)
			}
		})
	}
}

func TestEvaluateHostGone(t *testing.T) {
	rule := Rule{Name: "hg", Kind: KindHostGone, Severity: "info"}
	diff := map[string]config.HostDiff{
		"192.168.1.20": {Gone: true},
		"192.168.1.21": {New: true},
	}

	got := Evaluate([]Rule{rule}, diff, nil, nil, "", "", testNow)
	if len(got) != 1 {
		t.Fatalf("want 1 alert, got %d: %+v", len(got), got)
	}
	if got[0].Subject != "192.168.1.20" || got[0].Severity != "info" {
		t.Errorf("unexpected alert: %+v", got[0])
	}

	rule.Ignore = []string{"192.168.1.20"}
	if got := Evaluate([]Rule{rule}, diff, nil, nil, "", "", testNow); len(got) != 0 {
		t.Fatalf("ignored host should not alert, got %+v", got)
	}
}

func TestEvaluateGatewayMACChanged(t *testing.T) {
	rule := Rule{Name: "gw", Kind: KindGatewayMACChanged}

	tests := []struct {
		name     string
		rule     Rule
		cur      string
		prev     string
		wantFire bool
	}{
		{name: "fires on a changed MAC", rule: rule, cur: "aa:bb:cc:00:00:02", prev: "aa:bb:cc:00:00:01", wantFire: true},
		{name: "quiet when unchanged", rule: rule, cur: "aa:bb:cc:00:00:01", prev: "aa:bb:cc:00:00:01", wantFire: false},
		{name: "formatting differences are not a change", rule: rule, cur: "AA-BB-CC-00-00-01", prev: "aa:bb:cc:00:00:01", wantFire: false},
		{name: "first sighting is not a spoof", rule: rule, cur: "aa:bb:cc:00:00:01", prev: "", wantFire: false},
		{name: "lost gateway MAC is not a spoof", rule: rule, cur: "", prev: "aa:bb:cc:00:00:01", wantFire: false},
		{name: "ignored MAC stays silent", rule: Rule{Name: "gw", Kind: KindGatewayMACChanged, Ignore: []string{"aa:bb:cc:00:00:02"}}, cur: "aa:bb:cc:00:00:02", prev: "aa:bb:cc:00:00:01", wantFire: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Evaluate([]Rule{tt.rule}, nil, nil, nil, tt.cur, tt.prev, testNow)
			if tt.wantFire {
				if len(got) != 1 {
					t.Fatalf("want 1 alert, got %+v", got)
				}
				// The ARP-spoof canary must default to the highest severity.
				if got[0].Severity != "high" {
					t.Errorf("gateway alert severity = %q, want high", got[0].Severity)
				}
			} else if len(got) != 0 {
				t.Fatalf("want no alert, got %+v", got)
			}
		})
	}
}

func TestEvaluateSortsMostSevereFirst(t *testing.T) {
	rules := []Rule{
		{Name: "hg", Kind: KindHostGone, Severity: "info"},
		{Name: "po", Kind: KindPortOpened},
		{Name: "gw", Kind: KindGatewayMACChanged},
	}
	diff := map[string]config.HostDiff{
		"192.168.1.20": {Gone: true},
		"192.168.1.10": {PortsOpened: []string{"445"}}, // warn
	}

	got := Evaluate(rules, diff, nil, nil, "aa:bb:cc:00:00:02", "aa:bb:cc:00:00:01", testNow)
	if len(got) != 3 {
		t.Fatalf("want 3 alerts, got %+v", got)
	}
	wantOrder := []string{"high", "warn", "info"}
	for i, want := range wantOrder {
		if got[i].Severity != want {
			t.Errorf("alert[%d] severity = %q, want %q (full order: %+v)", i, got[i].Severity, want, got)
		}
	}

	// Determinism: same inputs, byte-identical output.
	again := Evaluate(rules, diff, nil, nil, "aa:bb:cc:00:00:02", "aa:bb:cc:00:00:01", testNow)
	for i := range got {
		if got[i] != again[i] {
			t.Fatalf("evaluation not deterministic at %d: %+v vs %+v", i, got[i], again[i])
		}
	}
}

func TestSuppressor(t *testing.T) {
	s := NewSuppressor(10 * time.Minute)
	a := Alert{Rule: "nd", Subject: "mac:aa:bb:cc:dd:ee:01", At: testNow}

	if !s.Allow(a) {
		t.Fatal("first occurrence should always pass")
	}

	// Watch-mode repeats inside the window collapse.
	for _, d := range []time.Duration{time.Minute, 5 * time.Minute, 9 * time.Minute} {
		repeat := a
		repeat.At = testNow.Add(d)
		if s.Allow(repeat) {
			t.Fatalf("repeat at +%v should be suppressed", d)
		}
	}

	// A different device on the same rule is a different fact.
	other := a
	other.Subject = "mac:aa:bb:cc:dd:ee:02"
	if !s.Allow(other) {
		t.Fatal("a different subject must not be suppressed")
	}

	// After the window a genuine re-occurrence alerts again.
	back := a
	back.At = testNow.Add(11 * time.Minute)
	if !s.Allow(back) {
		t.Fatal("re-occurrence after the cooldown should pass")
	}

	// Non-positive cooldown suppresses nothing.
	none := NewSuppressor(0)
	if !none.Allow(a) || !none.Allow(a) {
		t.Fatal("zero cooldown should pass every alert")
	}
}

func TestSuppressorFilter(t *testing.T) {
	s := NewSuppressor(time.Hour)
	alerts := []Alert{
		{Rule: "nd", Subject: "a", At: testNow},
		{Rule: "nd", Subject: "b", At: testNow},
		{Rule: "nd", Subject: "a", At: testNow.Add(time.Second)}, // repeat
	}
	got := s.Filter(alerts)
	if len(got) != 2 || got[0].Subject != "a" || got[1].Subject != "b" {
		t.Fatalf("filter should drop only the repeat, got %+v", got)
	}
}
