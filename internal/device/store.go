package device

import (
	"encoding/json"
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

// Load reads the known devices. A missing or unreadable file yields an empty
// set: not knowing any devices yet is the normal state on first run, and it
// must not be reported as a failure.
func Load() map[string]Record {
	b, err := os.ReadFile(storePath())
	if err != nil {
		return map[string]Record{}
	}
	var recs []Record
	if json.Unmarshal(b, &recs) != nil {
		return map[string]Record{}
	}
	out := make(map[string]Record, len(recs))
	for _, r := range recs {
		out[r.Key] = r
	}
	return out
}

// Save writes the device set atomically.
//
// Records are stored as a sorted array rather than an object so the file has a
// stable byte-for-byte form: an unordered map would reshuffle on every write,
// making the file useless to diff and defeating the write-if-changed check that
// keeps watch mode from churning the disk every interval.
func Save(devices map[string]Record) error {
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
	devices := Load()
	rec, ok := devices[key]
	if !ok {
		return os.ErrNotExist
	}
	rec.Name = name
	devices[key] = rec
	return Save(devices)
}
