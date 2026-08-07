package alert

import (
	"testing"
	"time"

	"github.com/Emre-Diricanli/ndscan/internal/config"
	"github.com/Emre-Diricanli/ndscan/internal/device"
)

// Watch mode runs every 60s. The failure mode this package exists to prevent is
// telling a person the same thing 60 times an hour.
func TestSuppressorCollapsesWatchModeRepeats(t *testing.T) {
	rules := Defaults()
	now := time.Now()
	devices := map[string]device.Record{
		"mac:3c:22:fb:11:22:33": {Key: "mac:3c:22:fb:11:22:33", Confidence: "stable", Name: "nas"},
	}
	newKeys := []string{"mac:3c:22:fb:11:22:33"}

	s := NewSuppressor(time.Hour)
	fired := 0
	// Simulate an hour of watch intervals reporting the same new device.
	for i := 0; i < 60; i++ {
		at := now.Add(time.Duration(i) * time.Minute)
		for _, a := range Evaluate(rules, nil, devices, newKeys, "", "", at) {
			if s.Allow(a) {
				fired++
			}
		}
	}
	if fired != 1 {
		t.Errorf("fired %d times over an hour of watch intervals, want 1", fired)
	}
}

// A phone that re-randomizes its MAC produces a brand-new "device" every time
// it reconnects. Alerting on those is noise that would train a user to ignore
// the alert that matters.
func TestRandomizedMACChurnDoesNotAlert(t *testing.T) {
	rules := Defaults()
	now := time.Now()

	// Three "arrivals" that are really one phone re-randomizing.
	fired := 0
	for i, mac := range []string{"02:aa:bb:cc:dd:01", "02:aa:bb:cc:dd:02", "02:aa:bb:cc:dd:03"} {
		k := device.KeyFor("192.0.2.50", mac)
		devices := map[string]device.Record{k.ID: {Key: k.ID, Confidence: k.Confidence.String()}}
		fired += len(Evaluate(rules, nil, devices, []string{k.ID}, "", "", now.Add(time.Duration(i)*time.Hour)))
	}
	if fired != 0 {
		t.Errorf("randomized-MAC churn produced %d alerts, want 0 by default", fired)
	}

	// But a real device with stable hardware identity must still alert.
	k := device.KeyFor("192.0.2.60", "3c:22:fb:11:22:33")
	devices := map[string]device.Record{k.ID: {Key: k.ID, Confidence: k.Confidence.String()}}
	if got := Evaluate(rules, nil, devices, []string{k.ID}, "", "", now); len(got) == 0 {
		t.Error("a genuinely new stable device must still alert")
	}
}

// The ARP-spoof canary is the highest-value rule; it must be on by default.
func TestGatewayMACChangeAlertsByDefault(t *testing.T) {
	got := Evaluate(Defaults(), nil, nil, nil, "aa:bb:cc:dd:ee:ff", "11:22:33:44:55:66", time.Now())
	if len(got) == 0 {
		t.Fatal("a changed gateway MAC must alert out of the box")
	}
	if got[0].Severity != "high" {
		t.Errorf("gateway MAC change severity = %q, want high (it is an ARP-spoof canary)", got[0].Severity)
	}
}

// Alerts must be ordered so the most serious thing is what a person sees first.
func TestAlertsSortMostSevereFirst(t *testing.T) {
	diff := map[string]config.HostDiff{
		"192.0.2.1": {PortsOpened: []string{"22"}},
		"192.0.2.2": {Gone: true},
	}
	got := Evaluate(Defaults(), diff, nil, nil, "aa:bb:cc:dd:ee:ff", "11:22:33:44:55:66", time.Now())
	if len(got) < 2 {
		t.Skipf("need multiple alerts to check ordering, got %d", len(got))
	}
	rank := map[string]int{"high": 3, "warn": 2, "info": 1, "": 0}
	for i := 1; i < len(got); i++ {
		if rank[got[i-1].Severity] < rank[got[i].Severity] {
			t.Errorf("alert %d (%s) outranks %d (%s): not sorted most-severe-first",
				i, got[i].Severity, i-1, got[i-1].Severity)
		}
	}
}
