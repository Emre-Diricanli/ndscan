package device

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"github.com/Emre-Diricanli/ndscan/internal/config"
	"github.com/Emre-Diricanli/ndscan/internal/userenv"
)

// The device set lives beside config and history as one JSON file. A home or
// office network produces tens to hundreds of devices, so a single document
// that is read and written whole stays simple and stays inspectable — a user
// can open it, see what ndscan thinks their network contains, and correct a
// name by hand.
func storePath() string { return filepath.Join(config.Dir(), "devices.json") }

// LoadChecked reads the known devices, distinguishing the two states Load
// used to merge. A missing file is the normal first-run state and yields an
// empty set with no error. A corrupt file is an error: it holds names a user
// typed by hand — the only human-authored data ndscan keeps — and reading it
// as "no devices known" is what lets the next Save destroy them.
func LoadChecked() (map[string]Record, error) {
	b, err := os.ReadFile(storePath())
	if err != nil {
		return map[string]Record{}, nil
	}
	var recs []Record
	if err := json.Unmarshal(b, &recs); err != nil {
		return map[string]Record{}, fmt.Errorf("devices.json is corrupt: fix or delete %s: %w", storePath(), err)
	}
	out := make(map[string]Record, len(recs))
	for _, r := range recs {
		out[r.Key] = r
	}
	return out, nil
}

// Load reads the known devices. A missing or unreadable file yields an empty
// set: not knowing any devices yet is the normal state on first run, and it
// must not be reported as a failure.
//
// A corrupt file also yields an empty set here, because the callers of this
// non-erroring form (internal/engine, cmd/ndscan) build on whatever set they
// get and their signatures cannot change from this package. The corruption is
// not silent, though: Save refuses to overwrite a store it cannot parse, so
// the file survives and the failed write is reported through
// engine.Record.Warnings. Callers that can surface an error should use
// LoadChecked instead.
func Load() map[string]Record {
	devices, _ := LoadChecked()
	return devices
}

// Save writes the device set atomically.
//
// Records are stored as a sorted array rather than an object so the file has a
// stable byte-for-byte form: an unordered map would reshuffle on every write,
// making the file useless to diff and defeating the write-if-changed check that
// keeps watch mode from churning the disk every interval.
func Save(devices map[string]Record) error {
	// Refuse to overwrite a store that no longer parses. Load reads a corrupt
	// file as an empty set, so without this guard the very next scan would
	// atomically replace the file with that near-empty set and permanently
	// destroy every user-assigned name.
	//
	// The guard re-reads the bytes on disk rather than remembering that an
	// earlier Load failed (a package-level "poisoned" flag): it holds even
	// for a caller that saves without loading first, it cannot go stale when
	// the user repairs or deletes the file between runs, and it keeps the
	// rule in one place instead of splitting it across Load and Save.
	if existing, err := os.ReadFile(storePath()); err == nil {
		var recs []Record
		if err := json.Unmarshal(existing, &recs); err != nil {
			return fmt.Errorf("devices.json is corrupt; refusing to overwrite it — fix or delete %s", storePath())
		}
	}
	keys := make([]string, 0, len(devices))
	for k := range devices {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	recs := make([]Record, 0, len(keys))
	for _, k := range keys {
		recs = append(recs, devices[k])
	}

	b, err := json.MarshalIndent(recs, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(config.Dir(), 0o755); err != nil {
		return err
	}
	// ndscan relaunches itself under sudo for privileged scans, so anything it
	// creates can end up owned by root. Left that way, every later unprivileged
	// run fails to write and silently loses its device history.
	_ = userenv.Chown(config.Dir())
	return config.WriteFileAtomic(storePath(), b, 0o644)
}

// Rename assigns a user-chosen name to a device.
//
// The name is stored separately from discovered hostnames and always wins over
// them, so a device that starts advertising a different name does not overwrite
// what its owner decided to call it.
func Rename(key, name string) error {
	// LoadChecked rather than Load: on a corrupt store the plain form reads as
	// "no devices", and the rename would fail with a misleading not-exist
	// instead of saying the file needs repair.
	devices, err := LoadChecked()
	if err != nil {
		return err
	}
	rec, ok := devices[key]
	if !ok {
		return os.ErrNotExist
	}
	rec.Name = name
	devices[key] = rec
	return Save(devices)
}
