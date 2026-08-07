package main

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/Emre-Diricanli/ndscan/internal/config"
	"github.com/Emre-Diricanli/ndscan/internal/timeline"
)

// The reproduction that motivated this wave: `ndscan diff` read the timeline
// unscoped, so asking about one network reported another network's changes —
// confidently, in a command documented as safe for cron.
func TestDiffDoesNotLeakAnotherNetworksChanges(t *testing.T) {
	t.Setenv("NDSCAN_CONFIG_DIR", t.TempDir())
	now := time.Now()

	// A real scan of 192.168.2.0/24 recorded real changes.
	scanned := config.ScanKey{Targets: []string{"192.168.2.0/24"}, Preset: "quick", Fast: true}
	for _, ip := range []string{"192.168.2.205", "192.168.2.227"} {
		if err := timeline.Append(timeline.Event{
			Timestamp: now, Type: timeline.EventHostSeen,
			DeviceKey: "ip:" + ip, IP: ip,
			Scope: scanned.Scope(), Run: "run-1",
		}); err != nil {
			t.Fatal(err)
		}
	}

	// A different network has a baseline but no recorded events of its own.
	other := config.ScanKey{Targets: []string{"10.0.0.0/24"}, Preset: "quick", Fast: true}
	if err := config.SaveHistory(other, []config.HostSnapshot{{IP: "10.0.0.5", Up: true}}); err != nil {
		t.Fatal(err)
	}

	o := diffOptions{targets: []string{"10.0.0.0/24"}, preset: "quick", fast: true}
	var buf bytes.Buffer
	code, err := runDiff(&buf, o)
	if err != nil {
		t.Fatal(err)
	}

	for _, leaked := range []string{"192.168.2.205", "192.168.2.227"} {
		if strings.Contains(buf.String(), leaked) {
			t.Errorf("diff of 10.0.0.0/24 reported %s from another network:\n%s", leaked, buf.String())
		}
	}
	if code == diffExitChanged {
		t.Errorf("reported changes for a network with none recorded:\n%s", buf.String())
	}
}

// Events written before scoping existed cannot be attributed to any signature.
// They are kept as history but must not be folded into a scoped answer.
func TestLegacyUnscopedEventsAreNotAttributed(t *testing.T) {
	t.Setenv("NDSCAN_CONFIG_DIR", t.TempDir())
	key := config.ScanKey{Targets: []string{"192.0.2.0/24"}, Preset: "quick"}

	if err := timeline.Append(timeline.Event{
		Timestamp: time.Now(), Type: timeline.EventHostSeen,
		DeviceKey: "ip:192.0.2.77", IP: "192.0.2.77", // no Scope: pre-scoping record
	}); err != nil {
		t.Fatal(err)
	}
	if err := config.SaveHistory(key, []config.HostSnapshot{{IP: "192.0.2.1", Up: true}}); err != nil {
		t.Fatal(err)
	}

	var buf bytes.Buffer
	if _, err := runDiff(&buf, diffOptions{targets: []string{"192.0.2.0/24"}, preset: "quick"}); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(buf.String(), "192.0.2.77") {
		t.Errorf("an unscoped legacy event was attributed to a signature:\n%s", buf.String())
	}
}
