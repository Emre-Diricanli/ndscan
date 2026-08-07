package main

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/Emre-Diricanli/ndscan/internal/device"
	"github.com/Emre-Diricanli/ndscan/internal/timeline"
)

func seedDeviceRecord(t *testing.T, rec device.Record) {
	t.Helper()
	devices := device.Load()
	devices[rec.Key] = rec
	if err := device.Save(devices); err != nil {
		t.Fatalf("device.Save: %v", err)
	}
}

// A fresh install must say what to do rather than print an empty table.
func TestDevicesListEmptyIsHelpful(t *testing.T) {
	t.Setenv("NDSCAN_CONFIG_DIR", t.TempDir())
	var buf bytes.Buffer
	if err := listDevices(&buf, false); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "run a scan first") {
		t.Errorf("empty inventory should say what to do:\n%s", buf.String())
	}
}

func TestDevicesListRendersLabels(t *testing.T) {
	t.Setenv("NDSCAN_CONFIG_DIR", t.TempDir())
	now := time.Now()
	seedDeviceRecord(t, device.Record{
		Key: "mac:3c:22:fb:11:22:33", MAC: "3c:22:fb:11:22:33", Vendor: "Apple",
		Name: "kids-tablet", Addresses: []string{"192.0.2.10"},
		FirstSeen: now.Add(-48 * time.Hour), LastSeen: now,
	})
	var buf bytes.Buffer
	if err := listDevices(&buf, false); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"kids-tablet", "192.0.2.10", "Apple"} {
		if !strings.Contains(buf.String(), want) {
			t.Errorf("output missing %q:\n%s", want, buf.String())
		}
	}
}

// The questions the timeline was built to answer, now reachable.
func TestDevicesShowSurfacesHistory(t *testing.T) {
	t.Setenv("NDSCAN_CONFIG_DIR", t.TempDir())
	now := time.Now()
	key := "mac:3c:22:fb:11:22:33"
	seedDeviceRecord(t, device.Record{Key: key, MAC: "3c:22:fb:11:22:33", Addresses: []string{"192.0.2.10"}, LastSeen: now})

	if err := timeline.Append(timeline.Event{
		Timestamp: now.Add(-time.Hour), Type: timeline.EventPortOpened,
		DeviceKey: key, IP: "192.0.2.10", Port: 445, Scope: "s", Run: "r",
	}); err != nil {
		t.Fatal(err)
	}

	var buf bytes.Buffer
	if err := showDevice(&buf, key, false); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "port 445 opened") {
		t.Errorf("show did not surface the port history:\n%s", buf.String())
	}
}

func TestDevicesShowUnknownKey(t *testing.T) {
	t.Setenv("NDSCAN_CONFIG_DIR", t.TempDir())
	var buf bytes.Buffer
	err := showDevice(&buf, "mac:00:00:00:00:00:01", false)
	if err == nil {
		t.Fatal("showing an unrecorded device should fail rather than print nothing")
	}
	if !strings.Contains(err.Error(), "devices list") {
		t.Errorf("error should point at how to find valid keys: %v", err)
	}
}

// A user-assigned name must beat whatever the device advertises.
func TestDevicesNameWinsOverAdvertised(t *testing.T) {
	t.Setenv("NDSCAN_CONFIG_DIR", t.TempDir())
	key := "mac:3c:22:fb:11:22:33"
	seedDeviceRecord(t, device.Record{Key: key, Hostnames: []string{"android-1234"}, LastSeen: time.Now()})

	if err := device.Rename(key, "kids-tablet"); err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	if err := listDevices(&buf, false); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "kids-tablet") {
		t.Errorf("assigned name missing:\n%s", buf.String())
	}
	if strings.Contains(buf.String(), "android-1234") {
		t.Errorf("advertised name displaced the assigned one:\n%s", buf.String())
	}
}
