package engine

import (
	"testing"
	"time"

	"github.com/Emre-Diricanli/ndscan/internal/config"
	"github.com/Emre-Diricanli/ndscan/internal/timeline"
	"github.com/Emre-Diricanli/ndscan/internal/ui"
	"github.com/Emre-Diricanli/ndscan/internal/vendor"
)

func recordPlan() Plan {
	return Plan{Targets: []string{"192.0.2.0/24"}, Preset: "quick"}
}

func complete(rows ...ui.Row) Outcome {
	return Outcome{Status: StatusComplete, Rows: rows, MACs: map[string]string{}}
}

// Persist must reject a run that cannot be trusted, and reject it for every
// store at once — history, devices, and the timeline. Recording an interrupted
// scan reports the network as gone now and as new next time.
func TestPersistIgnoresIncompleteRuns(t *testing.T) {
	rows := []ui.Row{{IP: "192.0.2.1", Up: true, MAC: "3c:22:fb:11:22:33"}}
	cases := []struct {
		name string
		out  Outcome
	}{
		{"cancelled", Outcome{Status: StatusCancelled, Rows: rows}},
		{"partial", Outcome{Status: StatusPartial, Rows: rows, Failed: 2}},
		{"failed", Outcome{Status: StatusFailed, Rows: rows}},
		{"found nothing", Outcome{Status: StatusComplete}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("NDSCAN_CONFIG_DIR", t.TempDir())
			e := New()
			now := time.Now()

			// Establish a baseline from a good run first, so the test shows the
			// bad one is rejected rather than that nothing was ever written.
			e.Persist(complete(rows...), recordPlan(), now, vendor.DB{})
			before, _ := timeline.Devices()

			rec := e.Persist(tc.out, recordPlan(), now.Add(time.Minute), vendor.DB{})
			if rec.Comparable() {
				t.Error("an untrustworthy run must not be reported as comparable")
			}
			if len(rec.Events) != 0 {
				t.Errorf("wrote %d timeline events for an incomplete run", len(rec.Events))
			}
			if len(rec.NewDevices) != 0 {
				t.Errorf("recorded %d new devices for an incomplete run", len(rec.NewDevices))
			}
			after, _ := timeline.Devices()
			if len(after) != len(before) {
				t.Errorf("timeline grew from %d to %d devices on an incomplete run", len(before), len(after))
			}
		})
	}
}

// The first scan of a signature has nothing to compare against, so every host
// would read as new. Recording that would date every device's arrival to
// whenever ndscan was installed rather than when it actually appeared.
func TestFirstScanIsNotAnEventStorm(t *testing.T) {
	t.Setenv("NDSCAN_CONFIG_DIR", t.TempDir())
	e := New()
	now := time.Now()

	rec := e.Persist(complete(
		ui.Row{IP: "192.0.2.1", Up: true, MAC: "3c:22:fb:11:22:33", Ports: []string{"22/tcp ssh"}},
		ui.Row{IP: "192.0.2.2", Up: true, MAC: "b8:27:eb:aa:bb:cc"},
	), recordPlan(), now, vendor.DB{})

	if len(rec.Events) != 0 {
		t.Errorf("first scan wrote %d events, want none: %+v", len(rec.Events), rec.Events)
	}
	// Devices are still learned — we know they exist, we just have no evidence
	// about when they arrived.
	if len(rec.Devices) != 2 {
		t.Errorf("devices = %d, want 2 learned on the first scan", len(rec.Devices))
	}
}

// A previous snapshot that is empty but not nil reaches config.Diff, which only
// short-circuits on nil — so without the guard in appendTimeline every host in
// the next scan reads as an arrival. That state is reachable: a history file
// holding an empty array loads as a non-nil empty slice.
func TestEmptyPreviousSnapshotIsNotAnArrival(t *testing.T) {
	t.Setenv("NDSCAN_CONFIG_DIR", t.TempDir())
	key := config.ScanKey{Targets: []string{"192.0.2.0/24"}, Preset: "quick"}
	if err := config.SaveHistory(key, []config.HostSnapshot{}); err != nil {
		t.Fatal(err)
	}
	if prev := config.LoadHistory(key); prev == nil || len(prev) != 0 {
		t.Fatalf("precondition: want a non-nil empty snapshot, got %#v", prev)
	}

	rec := New().Persist(complete(
		ui.Row{IP: "192.0.2.1", Up: true, MAC: "3c:22:fb:11:22:33"},
		ui.Row{IP: "192.0.2.2", Up: true, MAC: "b8:27:eb:aa:bb:cc"},
	), recordPlan(), time.Now(), vendor.DB{})

	if len(rec.Events) != 0 {
		t.Errorf("wrote %d events against an empty baseline, want none: %+v", len(rec.Events), rec.Events)
	}
}

// The point of the whole wave: a real change becomes a durable, queryable fact.
func TestPersistRecordsRealChanges(t *testing.T) {
	t.Setenv("NDSCAN_CONFIG_DIR", t.TempDir())
	e := New()
	t0 := time.Now().Add(-time.Hour)
	mac := "3c:22:fb:11:22:33"

	// Baseline: one host with ssh open.
	e.Persist(complete(
		ui.Row{IP: "192.0.2.1", Up: true, MAC: mac, Ports: []string{"22/tcp ssh"}},
	), recordPlan(), t0, vendor.DB{})

	// Later: it opened 445, and a second host appeared.
	rec := e.Persist(complete(
		ui.Row{IP: "192.0.2.1", Up: true, MAC: mac, Ports: []string{"22/tcp ssh", "445/tcp smb"}},
		ui.Row{IP: "192.0.2.9", Up: true, MAC: "b8:27:eb:aa:bb:cc"},
	), recordPlan(), t0.Add(time.Hour), vendor.DB{})

	if !rec.Comparable() {
		t.Fatal("a clean second scan should be comparable")
	}
	if len(rec.NewDevices) != 1 {
		t.Errorf("new devices = %v, want exactly the arrival", rec.NewDevices)
	}

	var opened, seen int
	for _, ev := range rec.Events {
		switch ev.Type {
		case timeline.EventPortOpened:
			opened++
			if ev.Port != 445 {
				t.Errorf("port opened = %d, want 445", ev.Port)
			}
		case timeline.EventHostSeen:
			seen++
		}
	}
	if opened != 1 || seen != 1 {
		t.Errorf("events: %d opened, %d seen; want 1 and 1 (%+v)", opened, seen, rec.Events)
	}

	// And the fact is queryable afterwards, which is the whole point.
	key := "mac:" + mac
	ph, err := timeline.PortHistory(key, 445)
	if err != nil || len(ph) != 1 {
		t.Errorf("PortHistory(445) = %+v (err %v), want the opening recorded", ph, err)
	}
}

// A device that changes address must stay one device in the timeline, or the
// log records a departure and an arrival for a machine that never moved.
func TestTimelineFollowsADeviceAcrossLeases(t *testing.T) {
	t.Setenv("NDSCAN_CONFIG_DIR", t.TempDir())
	e := New()
	t0 := time.Now().Add(-2 * time.Hour)
	mac := "3c:22:fb:11:22:33"

	e.Persist(complete(ui.Row{IP: "192.0.2.1", Up: true, MAC: mac}), recordPlan(), t0, vendor.DB{})
	rec := e.Persist(complete(
		ui.Row{IP: "192.0.2.1", Up: true, MAC: mac, Ports: []string{"22/tcp ssh"}},
	), recordPlan(), t0.Add(time.Hour), vendor.DB{})

	for _, ev := range rec.Events {
		if ev.DeviceKey != "mac:"+mac {
			t.Errorf("event keyed by %q, want the hardware identity", ev.DeviceKey)
		}
	}
}

func TestSplitPort(t *testing.T) {
	cases := []struct {
		in        string
		wantPort  int
		wantProto string
	}{
		// What config.Diff actually produces today: bare numbers.
		{"22", 22, ""},
		{"445", 445, ""},
		// The fuller forms, in case the diff stops discarding the protocol.
		{"22/tcp", 22, "tcp"},
		{"53/udp dns", 53, "udp"},
		{"", 0, ""},
		{"notaport", 0, ""},
	}
	for _, tc := range cases {
		t.Run(tc.in, func(t *testing.T) {
			p, proto := splitPort(tc.in)
			if p != tc.wantPort || proto != tc.wantProto {
				t.Errorf("splitPort(%q) = (%d, %q), want (%d, %q)", tc.in, p, proto, tc.wantPort, tc.wantProto)
			}
		})
	}
}
