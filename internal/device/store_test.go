package device

import (
	"bytes"
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

// Missing and corrupt are different states and must never be conflated:
// missing is the normal first-run state and stays silent, corrupt is an
// error. Load keeps its non-erroring contract (an empty set) in both cases;
// LoadChecked is where the distinction lives.
func TestLoadStates(t *testing.T) {
	cases := []struct {
		name      string
		contents  []byte // nil = file absent
		wantErr   bool
		wantCount int
	}{
		{"missing file", nil, false, 0},
		{"corrupt file", []byte("{not json"), true, 0},
		// A truncated write leaves a zero-byte or partial file; that must read
		// as corrupt, not as "no devices known".
		{"empty file", []byte(""), true, 0},
		{"valid file", []byte(`[{"key":"ip:192.0.2.1","confidence":"ephemeral"}]`), false, 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("NDSCAN_CONFIG_DIR", t.TempDir())
			if tc.contents != nil {
				if err := os.WriteFile(storePath(), tc.contents, 0o644); err != nil {
					t.Fatal(err)
				}
			}
			got, err := LoadChecked()
			if (err != nil) != tc.wantErr {
				t.Fatalf("LoadChecked() error = %v, wantErr %v", err, tc.wantErr)
			}
			if len(got) != tc.wantCount {
				t.Errorf("LoadChecked() loaded %d record(s), want %d", len(got), tc.wantCount)
			}
			if plain := Load(); len(plain) != tc.wantCount {
				t.Errorf("Load() loaded %d record(s), want %d", len(plain), tc.wantCount)
			}
		})
	}
}

// The data-destroying path the Save guard exists for: a corrupt store reads
// as empty, and the next Save must not atomically replace the file with that
// near-empty set — the original bytes survive for the user to repair.
func TestSaveRefusesToOverwriteCorruptStore(t *testing.T) {
	t.Setenv("NDSCAN_CONFIG_DIR", t.TempDir())
	corrupt := []byte("{not json")
	if err := os.WriteFile(storePath(), corrupt, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadChecked(); err == nil {
		t.Fatal("precondition failed: the store should read as corrupt")
	}
	if err := Save(map[string]Record{"ip:192.0.2.1": {Key: "ip:192.0.2.1"}}); err == nil {
		t.Fatal("Save must refuse to overwrite a corrupt store")
	}
	got, err := os.ReadFile(storePath())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, corrupt) {
		t.Fatalf("Save destroyed the store: got %q, want the original bytes untouched", got)
	}
}

// The guard reads the bytes on disk, so nothing stays poisoned: once the user
// deletes or repairs the file, saving works again.
func TestSaveWorksAfterCorruptStoreIsRemoved(t *testing.T) {
	t.Setenv("NDSCAN_CONFIG_DIR", t.TempDir())
	if err := os.WriteFile(storePath(), []byte("{not json"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := Save(map[string]Record{}); err == nil {
		t.Fatal("precondition failed: Save should refuse while the store is corrupt")
	}
	if err := os.Remove(storePath()); err != nil {
		t.Fatal(err)
	}
	devices := map[string]Record{"ip:192.0.2.1": {Key: "ip:192.0.2.1"}}
	if err := Save(devices); err != nil {
		t.Fatalf("Save after removing the corrupt file: %v", err)
	}
	if got := Load(); len(got) != 1 {
		t.Errorf("Load() after re-save = %v, want the new device set", got)
	}
}

// A rename on a corrupt store must report the corruption, not a misleading
// "device not found".
func TestRenameOnCorruptStoreReportsCorruption(t *testing.T) {
	t.Setenv("NDSCAN_CONFIG_DIR", t.TempDir())
	if err := os.WriteFile(storePath(), []byte("{not json"), 0o644); err != nil {
		t.Fatal(err)
	}
	err := Rename("ip:192.0.2.1", "nope")
	if err == nil || err == os.ErrNotExist {
		t.Fatalf("Rename on a corrupt store = %v, want a corruption error", err)
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
