package timeline

import (
	"os"
	"strings"
	"testing"
	"time"
)

// Independently verifies the durability claims the store makes.
//
// A torn final line must cost only that record, never the ones before it.
func TestTornWriteLosesOnlyTheLastRecord(t *testing.T) {
	t.Setenv("NDSCAN_CONFIG_DIR", t.TempDir())
	at := time.Date(2026, 5, 1, 10, 0, 0, 0, time.UTC)
	for i := 0; i < 3; i++ {
		if err := Append(Event{Type: EventHostSeen, Timestamp: at.Add(time.Duration(i) * time.Minute), DeviceKey: "mac:aa", IP: "192.0.2.1"}); err != nil {
			t.Fatal(err)
		}
	}
	// Simulate a crash mid-write: append a partial JSON record with no newline.
	p := eventPath(at)
	f, err := os.OpenFile(p, os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	f.WriteString(`{"type":"host_seen","timestamp":"2026-05-01T10`)
	f.Close()

	got, err := History("mac:aa")
	if err != nil {
		t.Fatalf("a torn tail must not fail the whole read: %v", err)
	}
	if len(got) != 3 {
		t.Errorf("recovered %d records, want the 3 complete ones", len(got))
	}

	// A later append must repair the file, not compound the damage.
	if err := Append(Event{Type: EventHostSeen, Timestamp: at.Add(time.Hour), DeviceKey: "mac:aa", IP: "192.0.2.1"}); err != nil {
		t.Fatal(err)
	}
	got, _ = History("mac:aa")
	if len(got) != 4 {
		t.Errorf("after repair got %d records, want 4", len(got))
	}
	b, _ := os.ReadFile(p)
	if strings.Contains(string(b), `2026-05-01T10"`) || strings.Count(string(b), "\n") != 4 {
		t.Errorf("file left malformed after repair:\n%s", b)
	}
}

// Old records must stay readable when the struct gains fields.
func TestUnknownFieldsAreTolerated(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("NDSCAN_CONFIG_DIR", dir)
	at := time.Date(2026, 5, 2, 0, 0, 0, 0, time.UTC)
	if err := os.MkdirAll(timelineDir(), 0o755); err != nil {
		t.Fatal(err)
	}
	line := `{"type":"host_seen","timestamp":"2026-05-02T00:00:00Z","device_key":"mac:bb","ip":"192.0.2.2","somethingFromTheFuture":{"a":1}}` + "\n"
	if err := os.WriteFile(eventPath(at), []byte(line), 0o644); err != nil {
		t.Fatal(err)
	}
	got, err := History("mac:bb")
	if err != nil || len(got) != 1 {
		t.Fatalf("forward compatibility broken: got %d records, err %v", len(got), err)
	}
}
