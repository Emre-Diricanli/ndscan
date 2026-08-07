package timeline_test

import (
	"testing"
	"time"

	"github.com/Emre-Diricanli/ndscan/internal/device"
	"github.com/Emre-Diricanli/ndscan/internal/timeline"
	"github.com/Emre-Diricanli/ndscan/internal/ui"
	"github.com/Emre-Diricanli/ndscan/internal/vendor"
)

// The three Wave 2 pieces have to compose: a scan produces rows, rows produce
// device identities, and identities key the timeline. Each package is tested
// alone; this checks the seams between them.
func TestScanToDeviceToTimeline(t *testing.T) {
	t.Setenv("NDSCAN_CONFIG_DIR", t.TempDir())
	day1 := time.Date(2026, 6, 1, 9, 0, 0, 0, time.UTC)
	day2 := day1.Add(48 * time.Hour)

	// Day 1: a laptop appears on .10.
	rows1 := []ui.Row{{IP: "192.0.2.10", Up: true, Host: "laptop", MAC: "3c:22:fb:11:22:33", Ports: []string{"22/tcp ssh"}}}
	devices, added := device.Apply(nil, device.FromRows(rows1, nil, day1), vendor.DB{})
	if len(added) != 1 {
		t.Fatalf("added = %v, want one new device", added)
	}
	key := added[0]
	if err := timeline.Append(timeline.Event{
		Type: timeline.EventHostSeen, Timestamp: day1, DeviceKey: key, IP: "192.0.2.10",
	}); err != nil {
		t.Fatal(err)
	}
	if err := timeline.Append(timeline.Event{
		Type: timeline.EventPortOpened, Timestamp: day1, DeviceKey: key, IP: "192.0.2.10", Port: 22, Protocol: "tcp",
	}); err != nil {
		t.Fatal(err)
	}

	// Day 2: same laptop, new DHCP lease, and it opened a second port.
	rows2 := []ui.Row{{IP: "192.0.2.99", Up: true, Host: "laptop", MAC: "3c:22:fb:11:22:33", Ports: []string{"22/tcp ssh", "445/tcp smb"}}}
	devices, added = device.Apply(devices, device.FromRows(rows2, nil, day2), vendor.DB{})
	if len(added) != 0 {
		t.Errorf("the same laptop on a new lease was reported as a new device: %v", added)
	}
	if err := timeline.Append(timeline.Event{
		Type: timeline.EventPortOpened, Timestamp: day2, DeviceKey: key, IP: "192.0.2.99", Port: 445, Protocol: "tcp",
	}); err != nil {
		t.Fatal(err)
	}

	// The questions Wave 2 exists to answer.
	first, ok, err := timeline.FirstSeen(key)
	if err != nil || !ok || !first.Equal(day1) {
		t.Errorf("FirstSeen = %v (ok=%v, err=%v), want %v", first, ok, err, day1)
	}
	hist, err := timeline.History(key)
	if err != nil {
		t.Fatal(err)
	}
	if len(hist) != 3 {
		t.Errorf("history has %d events, want 3 across both days", len(hist))
	}
	// "When did 445 open?" — unanswerable before this wave.
	ph, err := timeline.PortHistory(key, 445)
	if err != nil || len(ph) != 1 || !ph[0].Timestamp.Equal(day2) {
		t.Errorf("PortHistory(445) = %+v (err=%v), want one event on day 2", ph, err)
	}

	// The device record must have kept both leases under one identity.
	rec := devices[key]
	if len(rec.Addresses) != 2 {
		t.Errorf("addresses = %v, want both leases under one device", rec.Addresses)
	}
	if rec.Label() != "laptop" {
		t.Errorf("Label() = %q, want the advertised name", rec.Label())
	}
}
