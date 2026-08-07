// Package config persists ndscan's TUI state: last-used scan settings,
// named profiles, and previous scan results (for change detection).
// Everything lives under ~/.config/ndscan/ as plain JSON.
package config

import (
	"bytes"
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/Emre-Diricanli/ndscan/internal/userenv"
)

// Settings mirrors the TUI form fields.
type Settings struct {
	Targets     string `json:"targets"`
	Preset      string `json:"preset"`
	Ports       string `json:"ports"`
	ShowMac     bool   `json:"show_mac"`
	ShowVendors bool   `json:"show_vendors"`
	RootScan    bool   `json:"root_scan"`
	Concurrency string `json:"concurrency"`
	HostTimeout string `json:"host_timeout"`
}

// Profile is a named, saved Settings snapshot.
type Profile struct {
	Name     string   `json:"name"`
	Settings Settings `json:"settings"`
}

// File is the on-disk layout of config.json.
type File struct {
	Last     *Settings `json:"last,omitempty"`
	Profiles []Profile `json:"profiles,omitempty"`
}

func dir() string {
	// NDSCAN_CONFIG_DIR overrides the location (used by tests).
	if d := os.Getenv("NDSCAN_CONFIG_DIR"); d != "" {
		return d
	}
	if d := os.Getenv("NDSCAN_USER_CONFIG_DIR"); d != "" {
		return filepath.Join(d, "ndscan")
	}
	if d, err := os.UserConfigDir(); err == nil {
		return filepath.Join(d, "ndscan")
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".config", "ndscan")
}

// Dir is the directory ndscan keeps its state in.
//
// Exported so sibling packages store their data alongside config and history
// rather than each re-deriving the location. Three copies of this resolution
// would drift the first time the override rules change, and the symptom would
// be state silently written somewhere nobody looks.
func Dir() string { return dir() }

func configPath() string { return filepath.Join(dir(), "config.json") }
func historyDir() string { return filepath.Join(dir(), "history") }

// Load reads config.json; a missing or unreadable file yields an empty File.
func Load() File {
	var f File
	b, err := os.ReadFile(configPath())
	if err != nil {
		return f
	}
	_ = json.Unmarshal(b, &f)
	return f
}

// Save writes config.json, creating the directory as needed.
func Save(f File) error {
	if err := os.MkdirAll(dir(), 0o755); err != nil {
		return err
	}
	_ = userenv.Chown(dir())
	b, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return err
	}
	return writeIfChanged(configPath(), b, 0o644)
}

// SaveLast persists the most recently used settings.
func SaveLast(s Settings) error {
	f := Load()
	f.Last = &s
	return Save(f)
}

// UpsertProfile adds or replaces a named profile.
func UpsertProfile(name string, s Settings) error {
	f := Load()
	for i := range f.Profiles {
		if f.Profiles[i].Name == name {
			f.Profiles[i].Settings = s
			return Save(f)
		}
	}
	f.Profiles = append(f.Profiles, Profile{Name: name, Settings: s})
	sort.Slice(f.Profiles, func(i, j int) bool { return f.Profiles[i].Name < f.Profiles[j].Name })
	return Save(f)
}

// DeleteProfile removes a named profile if present.
func DeleteProfile(name string) error {
	f := Load()
	out := f.Profiles[:0]
	for _, p := range f.Profiles {
		if p.Name != name {
			out = append(out, p)
		}
	}
	f.Profiles = out
	return Save(f)
}

// ----- scan history (for diffing consecutive scans of the same targets) -----

// HostSnapshot is the minimal per-host state we remember between scans.
//
// Up is recorded explicitly because a host that stopped responding is a
// different event from a host whose ports all closed. Without it, a machine
// that went offline diffs as "every port closed" while the host itself appears
// to still be there — the opposite of what happened.
type HostSnapshot struct {
	IP    string   `json:"ip"`
	Host  string   `json:"host,omitempty"`
	Up    bool     `json:"up"`
	Ports []string `json:"ports,omitempty"` // bare port labels, e.g. "22/tcp ssh"
}

// ScanKey identifies "the same scan" across runs. Two scans are comparable only
// when every field matches, because each one changes which hosts or ports the
// scan could possibly have found.
//
// This is a struct rather than a positional argument list on purpose. It was
// previously three bare strings, and the front ends drifted: the web passed ""
// for Ports while the TUI passed the real value, so the two never shared a
// baseline and neither could see the other's history. A named field per input
// makes an omission visible at the call site instead of silent.
type ScanKey struct {
	Targets []string
	Ports   string
	Preset  string
	// Fast records whether this was the native ARP+TCP sweep rather than an
	// nmap scan. The two probe different things and legitimately find different
	// hosts, so mixing them under one key manufactures phantom
	// appeared/disappeared events on every alternation.
	Fast bool
}

// signature renders the key as the stable string the on-disk name hashes.
func (k ScanKey) signature() string {
	t := append([]string(nil), k.Targets...)
	sort.Strings(t)
	mode := "nmap"
	if k.Fast {
		mode = "fast"
	}
	return strings.Join(t, ",") + "|" + k.Ports + "|" + k.Preset + "|" + mode
}

// Scope is a stable identifier for "the same scan", suitable for tagging
// records in other stores so they can be filtered back to the scan that
// produced them.
//
// It is derived from the same canonical signature the history filename uses, so
// a second store cannot drift into its own interpretation of what makes two
// scans comparable — the timeline previously had no scope at all, and `ndscan
// diff` consequently reported changes from whichever network happened to be
// scanned last.
func (k ScanKey) Scope() string { return historyKey(k) }

// historyKey identifies "the same scan" across runs.
func historyKey(k ScanKey) string {
	h := sha1.Sum([]byte(k.signature()))
	return hex.EncodeToString(h[:])
}

func historyPath(k ScanKey) string {
	return filepath.Join(historyDir(), historyKey(k)+".json")
}

// LoadHistory returns the previous snapshot for this scan signature, or nil.
func LoadHistory(k ScanKey) []HostSnapshot {
	b, err := os.ReadFile(historyPath(k))
	if err != nil {
		return nil
	}
	var snaps []HostSnapshot
	if json.Unmarshal(b, &snaps) != nil {
		return nil
	}
	return snaps
}

// SaveHistory stores the snapshot for this scan signature.
//
// Callers must not reach here with the results of a cancelled, failed, or
// partial scan: an incomplete run looks exactly like a network where everything
// disappeared, and persisting it as the baseline makes the *next* scan report
// the whole network as new. Eligibility is the caller's decision because only
// it knows how the run terminated; SaveEligible states the rule in one place.
func SaveHistory(k ScanKey, snaps []HostSnapshot) error {
	if err := os.MkdirAll(historyDir(), 0o755); err != nil {
		return err
	}
	_ = userenv.Chown(historyDir())
	b, err := json.MarshalIndent(snaps, "", "  ")
	if err != nil {
		return err
	}
	return writeIfChanged(historyPath(k), b, 0o644)
}

// SaveEligible reports whether a finished scan may become the new baseline.
//
// The three front ends each answered this question separately and gave three
// different answers — the web saved unconditionally, including on cancellation,
// which corrupted history for every later run. Centralising the rule is what
// keeps them from drifting apart again.
//
// An empty result set is rejected even when the scan reported success: finding
// zero hosts almost always means the machine lost its network (VPN dropped,
// Wi-Fi roamed) rather than that the network emptied out, and treating it as
// truth discards a good baseline in favour of a useless one.
func SaveEligible(cancelled bool, failed int, hosts int) bool {
	return !cancelled && failed == 0 && hosts > 0
}

// WriteFileAtomic writes data to path via a temp file and a rename, skipping
// the write entirely when the contents already match.
//
// Exported for sibling packages that persist state alongside config: the
// same-contents check is what keeps watch mode from rewriting files every
// interval, and the rename is what stops an interrupted write from leaving
// truncated JSON behind.
func WriteFileAtomic(path string, data []byte, perm os.FileMode) error {
	return writeIfChanged(path, data, perm)
}

// writeIfChanged avoids watch-mode disk churn and replaces files atomically,
// so an interrupted write cannot leave config or history as truncated JSON.
func writeIfChanged(path string, data []byte, perm os.FileMode) error {
	if old, err := os.ReadFile(path); err == nil && bytes.Equal(old, data) {
		return nil
	}
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".ndscan-*.tmp")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	ok := false
	defer func() {
		_ = tmp.Close()
		if !ok {
			_ = os.Remove(tmpPath)
		}
	}()
	if err := tmp.Chmod(perm); err != nil {
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		return err
	}
	if err := tmp.Sync(); err != nil {
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := userenv.Chown(tmpPath); err != nil {
		return err
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return err
	}
	ok = true
	return nil
}

// ----- diff -----

// HostDiff describes how one host changed between two scans.
type HostDiff struct {
	New         bool     // host wasn't in the previous scan
	Gone        bool     // host was in the previous scan but not this one
	PortsOpened []string // port numbers newly open
	PortsClosed []string // port numbers no longer open
}

// Changed reports whether anything about the host differs.
func (d HostDiff) Changed() bool {
	return d.New || d.Gone || len(d.PortsOpened) > 0 || len(d.PortsClosed) > 0
}

// presentHosts indexes the hosts a snapshot says were actually on the network.
//
// A host is dropped only when the set demonstrably tracks liveness — that is,
// when at least one entry is marked up. Two situations produce a set where
// nobody is up, and neither means "the network is empty":
//
//   - a history file written before HostSnapshot carried Up, which decodes as
//     all-false and would otherwise diff as the whole network vanishing the
//     first time a user upgrades;
//   - a caller that builds snapshots without setting Up at all.
//
// Silently discarding every host in those cases would be a worse failure than
// the one this field exists to fix, so the conservative reading wins: absence
// is only inferred from a set that is clearly using the field.
func presentHosts(snaps []HostSnapshot) map[string]HostSnapshot {
	tracksLiveness := false
	for _, s := range snaps {
		if s.Up {
			tracksLiveness = true
			break
		}
	}
	out := make(map[string]HostSnapshot, len(snaps))
	for _, s := range snaps {
		if tracksLiveness && !s.Up {
			continue
		}
		out[s.IP] = s
	}
	return out
}

// portNum reduces "22/tcp ssh" to "22".
func portNum(label string) string {
	for i, r := range label {
		if r < '0' || r > '9' {
			if i == 0 {
				return label
			}
			return label[:i]
		}
	}
	return label
}

// Diff compares the current scan against the previous snapshot, keyed by IP.
// The returned map includes an entry for every changed host, including hosts
// that disappeared (Gone=true).
func Diff(prev []HostSnapshot, cur []HostSnapshot) map[string]HostDiff {
	if prev == nil {
		return nil // first scan of this signature: nothing to compare
	}
	// A host recorded as down is not present on the network, so it takes part in
	// the diff as an absence rather than as a host with no open ports. Older
	// snapshots predate the Up field and decode as false; treating those as down
	// would report the entire previous scan as gone, so a snapshot set that
	// knows about nobody being up is read as a pre-Up file and taken at face
	// value.
	prevByIP := presentHosts(prev)
	curByIP := presentHosts(cur)

	out := map[string]HostDiff{}

	seen := map[string]bool{}
	for _, c := range cur {
		if _, present := curByIP[c.IP]; !present {
			continue // scanned and found down: handled as an absence below
		}
		seen[c.IP] = true
		p, existed := prevByIP[c.IP]
		if !existed {
			out[c.IP] = HostDiff{New: true}
			continue
		}
		prevPorts := map[string]bool{}
		for _, lbl := range p.Ports {
			prevPorts[portNum(lbl)] = true
		}
		curPorts := map[string]bool{}
		for _, lbl := range c.Ports {
			curPorts[portNum(lbl)] = true
		}
		var d HostDiff
		for n := range curPorts {
			if !prevPorts[n] {
				d.PortsOpened = append(d.PortsOpened, n)
			}
		}
		for n := range prevPorts {
			if !curPorts[n] {
				d.PortsClosed = append(d.PortsClosed, n)
			}
		}
		sort.Strings(d.PortsOpened)
		sort.Strings(d.PortsClosed)
		if d.Changed() {
			out[c.IP] = d
		}
	}
	for ip := range prevByIP {
		if !seen[ip] {
			out[ip] = HostDiff{Gone: true}
		}
	}
	return out
}
