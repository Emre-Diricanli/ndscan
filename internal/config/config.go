// Package config persists ndscan's TUI state: last-used scan settings,
// named profiles, and previous scan results (for change detection).
// Everything lives under ~/.config/ndscan/ as plain JSON.
package config

import (
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
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
	if d, err := os.UserConfigDir(); err == nil {
		return filepath.Join(d, "ndscan")
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".config", "ndscan")
}

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
	b, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(configPath(), b, 0o644)
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
type HostSnapshot struct {
	IP    string   `json:"ip"`
	Host  string   `json:"host,omitempty"`
	Ports []string `json:"ports,omitempty"` // bare port labels, e.g. "22/tcp ssh"
}

// historyKey identifies "the same scan" across runs: same targets+ports+preset.
func historyKey(targets []string, ports, preset string) string {
	t := append([]string(nil), targets...)
	sort.Strings(t)
	h := sha1.Sum([]byte(strings.Join(t, ",") + "|" + ports + "|" + preset))
	return hex.EncodeToString(h[:])
}

func historyPath(targets []string, ports, preset string) string {
	return filepath.Join(historyDir(), historyKey(targets, ports, preset)+".json")
}

// LoadHistory returns the previous snapshot for this scan signature, or nil.
func LoadHistory(targets []string, ports, preset string) []HostSnapshot {
	b, err := os.ReadFile(historyPath(targets, ports, preset))
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
func SaveHistory(targets []string, ports, preset string, snaps []HostSnapshot) error {
	if err := os.MkdirAll(historyDir(), 0o755); err != nil {
		return err
	}
	b, err := json.MarshalIndent(snaps, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(historyPath(targets, ports, preset), b, 0o644)
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
	prevByIP := make(map[string]HostSnapshot, len(prev))
	for _, s := range prev {
		prevByIP[s.IP] = s
	}
	out := map[string]HostDiff{}

	seen := map[string]bool{}
	for _, c := range cur {
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
