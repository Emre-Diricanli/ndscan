package device

import (
	"os"
	"testing"
	"time"
)

func TestSaveLoadRoundTrip(t *testing.T) {
	t.Setenv("NDSCAN_CONFIG_DIR", t.TempDir())
	at := time.Date(2026, 3, 4, 5, 6, 7, 0, time.UTC)

	want := map[string]Record{
		"mac:3c:22:fb:11:22:33": {
			Key: "mac:3c:22:fb:11:22:33", MAC: "3c:22:fb:11:22:33",
			Vendor: "Apple", Confidence: "stable", Name: "emre-laptop",
			FirstSeen: at, LastSeen: at.Add(time.Hour),
			Addresses: []string{"192.0.2.9"}, Hostnames: []string{"laptop"},
		},
	}
	if err := Save(want); err != nil {
		t.Fatal(err)
	}
	got := Load()
	if len(got) != 1 {
		t.Fatalf("loaded %d records, want 1", len(got))
	}
	r := got["mac:3c:22:fb:11:22:33"]
	if r.Name != "emre-laptop" || r.Vendor != "Apple" || !r.FirstSeen.Equal(at) {
		t.Errorf("round trip lost data: %+v", r)
	}
}

// Not knowing any devices is the normal state on first run and must never
// surface as an error.
func TestLoadMissingFileIsEmpty(t *testing.T) {
	t.Setenv("NDSCAN_CONFIG_DIR", t.TempDir())
	if got := Load(); len(got) != 0 {
		t.Errorf("Load() on a fresh install = %v, want empty", got)
	}
}

// A hand-edited file that got mangled must not take the whole device list down
// with it — the user can fix a name by hand, so they can also break the file.
func TestLoadCorruptFileIsEmpty(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("NDSCAN_CONFIG_DIR", dir)
	if err := os.WriteFile(storePath(), []byte("{not json"), 0o644); err != nil {
		t.Fatal(err)
	}
	if got := Load(); len(got) != 0 {
		t.Errorf("Load() on corrupt input = %v, want empty", got)
	}
}

// Watch mode rewrites this file on every interval. An unstable byte ordering
// would defeat the write-if-changed check and churn the disk forever.
func TestSaveIsByteStable(t *testing.T) {
	t.Setenv("NDSCAN_CONFIG_DIR", t.TempDir())
	at := time.Now().UTC()
	devices := map[string]Record{
		"mac:aa:bb:cc:dd:ee:ff": {Key: "mac:aa:bb:cc:dd:ee:ff", FirstSeen: at, LastSeen: at},
		"ip:192.0.2.1":          {Key: "ip:192.0.2.1", FirstSeen: at, LastSeen: at},
		"mac:11:22:33:44:55:66": {Key: "mac:11:22:33:44:55:66", FirstSeen: at, LastSeen: at},
	}
	if err := Save(devices); err != nil {
		t.Fatal(err)
	}
	first, err := os.ReadFile(storePath())
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 5; i++ {
		if err := Save(devices); err != nil {
			t.Fatal(err)
		}
		again, err := os.ReadFile(storePath())
		if err != nil {
			t.Fatal(err)
		}
		if string(first) != string(again) {
			t.Fatalf("rewrite %d produced different bytes: map iteration order is leaking", i)
		}
	}
}

func TestRenameKeepsDiscoveredNames(t *testing.T) {
	t.Setenv("NDSCAN_CONFIG_DIR", t.TempDir())
	key := "mac:3c:22:fb:11:22:33"
	if err := Save(map[string]Record{key: {Key: key, Hostnames: []string{"android-1234"}}}); err != nil {
		t.Fatal(err)
	}
	if err := Rename(key, "kids-tablet"); err != nil {
		t.Fatal(err)
	}

	r := Load()[key]
	if r.Name != "kids-tablet" {
		t.Errorf("Name = %q, want the assigned name", r.Name)
	}
	// The advertised name is kept alongside, not replaced: it is still a fact
	// about the device.
	if len(r.Hostnames) != 1 || r.Hostnames[0] != "android-1234" {
		t.Errorf("Hostnames = %v, want the discovered name preserved", r.Hostnames)
	}
	if r.Label() != "kids-tablet" {
		t.Errorf("Label() = %q, want the user's name to win", r.Label())
	}
}

func TestRenameUnknownDevice(t *testing.T) {
	t.Setenv("NDSCAN_CONFIG_DIR", t.TempDir())
	if err := Rename("mac:00:00:00:00:00:01", "nope"); err == nil {
		t.Error("renaming a device we have never seen should fail rather than invent one")
	}
}
