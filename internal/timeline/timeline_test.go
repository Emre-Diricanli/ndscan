package timeline

import (
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sync"
	"testing"
	"time"
)

func at(day, clock string) time.Time {
	t, err := time.Parse(time.RFC3339, day+"T"+clock+"Z")
	if err != nil {
		panic(err)
	}
	return t
}

func TestAppendRoundTrip(t *testing.T) {
	t.Setenv("NDSCAN_CONFIG_DIR", t.TempDir())
	want := []Event{
		{Timestamp: at("2026-01-02", "03:04:05"), Type: EventHostSeen, DeviceKey: "device-a", IP: "192.0.2.1"},
		{Timestamp: at("2026-01-02", "03:05:05"), Type: EventPortOpened, DeviceKey: "device-a", IP: "192.0.2.1", Port: 445, Protocol: "tcp"},
	}
	for _, event := range want {
		if err := Append(event); err != nil {
			t.Fatal(err)
		}
	}
	got, err := History("device-a")
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("History() = %#v, want %#v", got, want)
	}
}

func TestReadCompatibilityAndTornTail(t *testing.T) {
	t.Setenv("NDSCAN_CONFIG_DIR", t.TempDir())
	if err := os.MkdirAll(timelineDir(), 0o755); err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name string
		data string
	}{
		{
			name: "unknown field",
			data: `{"timestamp":"2026-01-02T03:04:05Z","type":"host_seen","device_key":"device-a","ip":"192.0.2.1","future":{"value":1}}` + "\n",
		},
		{
			name: "truncated final line",
			data: `{"timestamp":"2026-01-02T03:04:05Z","type":"host_seen","device_key":"device-a","ip":"192.0.2.1"}` + "\n" + `{"timestamp":"2026`,
		},
		{
			name: "corrupt final line",
			data: `{"timestamp":"2026-01-02T03:04:05Z","type":"host_seen","device_key":"device-a","ip":"192.0.2.1"}` + "\n" + `{not json`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join(timelineDir(), "2026-01-02.jsonl")
			if err := os.WriteFile(path, []byte(tt.data), 0o644); err != nil {
				t.Fatal(err)
			}
			got, err := History("device-a")
			if err != nil {
				t.Fatal(err)
			}
			if len(got) != 1 || got[0].IP != "192.0.2.1" {
				t.Fatalf("History() = %#v, want one intact event", got)
			}
		})
	}
}

func TestQueries(t *testing.T) {
	t.Setenv("NDSCAN_CONFIG_DIR", t.TempDir())
	events := []Event{
		{Timestamp: at("2026-02-01", "10:00:00"), Type: EventHostSeen, DeviceKey: "b", IP: "192.0.2.2"},
		{Timestamp: at("2026-02-01", "09:00:00"), Type: EventHostSeen, DeviceKey: "a", IP: "192.0.2.1"},
		{Timestamp: at("2026-02-01", "11:00:00"), Type: EventPortOpened, DeviceKey: "a", IP: "192.0.2.1", Port: 445, Protocol: "tcp"},
		{Timestamp: at("2026-02-01", "12:00:00"), Type: EventPortOpened, DeviceKey: "a", IP: "192.0.2.1", Port: 22, Protocol: "tcp"},
		{Timestamp: at("2026-02-01", "13:00:00"), Type: EventPortClosed, DeviceKey: "a", IP: "192.0.2.1", Port: 445, Protocol: "tcp"},
		{Timestamp: at("2026-02-02", "09:00:00"), Type: EventHostSeen, DeviceKey: "a", IP: "192.0.2.9"},
	}
	for _, event := range events {
		if err := Append(event); err != nil {
			t.Fatal(err)
		}
	}

	tests := []struct {
		name  string
		check func(*testing.T)
	}{
		{"first and last seen", func(t *testing.T) {
			first, ok, err := FirstSeen("a")
			if err != nil || !ok || !first.Equal(at("2026-02-01", "09:00:00")) {
				t.Fatalf("FirstSeen() = %v, %v, %v", first, ok, err)
			}
			last, ok, err := LastSeen("a")
			if err != nil || !ok || !last.Equal(at("2026-02-02", "09:00:00")) {
				t.Fatalf("LastSeen() = %v, %v, %v", last, ok, err)
			}
		}},
		{"missing device", func(t *testing.T) {
			_, ok, err := FirstSeen("missing")
			if err != nil || ok {
				t.Fatalf("FirstSeen() ok = %v, err = %v", ok, err)
			}
		}},
		{"interleaved port history", func(t *testing.T) {
			got, err := PortHistory("a", 445)
			if err != nil || len(got) != 2 || got[0].Type != EventPortOpened || got[1].Type != EventPortClosed {
				t.Fatalf("PortHistory() = %#v, %v", got, err)
			}
		}},
		{"recent inclusive", func(t *testing.T) {
			got, err := recent(at("2026-02-01", "13:00:00"))
			if err != nil || len(got) != 2 {
				t.Fatalf("recent() has %d events, err = %v", len(got), err)
			}
		}},
		{"devices sorted", func(t *testing.T) {
			got, err := Devices()
			if err != nil || !reflect.DeepEqual(got, []string{"a", "b"}) {
				t.Fatalf("Devices() = %v, %v", got, err)
			}
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, tt.check)
	}
}

func TestPrune(t *testing.T) {
	t.Setenv("NDSCAN_CONFIG_DIR", t.TempDir())
	for _, day := range []string{"2026-01-01", "2026-01-02", "2026-01-03"} {
		if err := Append(Event{Timestamp: at(day, "12:00:00"), Type: EventHostSeen, DeviceKey: day, IP: "192.0.2.1"}); err != nil {
			t.Fatal(err)
		}
	}
	if err := Prune(at("2026-01-03", "00:00:00")); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(timelineDir())
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, entry := range entries {
		got = append(got, entry.Name())
	}
	want := []string{"2026-01-03.jsonl"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("files after Prune() = %v, want %v", got, want)
	}
}

func TestConcurrentAppend(t *testing.T) {
	t.Setenv("NDSCAN_CONFIG_DIR", t.TempDir())
	const count = 100
	var wg sync.WaitGroup
	errs := make(chan error, count)
	for i := 0; i < count; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			errs <- Append(Event{
				Timestamp: at("2026-03-01", "12:00:00").Add(time.Duration(i) * time.Second),
				Type:      EventHostSeen, DeviceKey: fmt.Sprintf("device-%03d", i), IP: "192.0.2.1",
			})
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	got, err := recent(time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != count {
		t.Fatalf("recent() has %d events, want %d", len(got), count)
	}
}
