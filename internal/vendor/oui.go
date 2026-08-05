package vendor

import (
	"bytes"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"

	"github.com/Emre-Diricanli/ndscan/internal/userenv"
)

type DB map[string]string

const sample = `00:11:22	AcmeCorp
00:25:96	D-Link
3C:5A:B4	TP-Link
48:5A:3F	Cisco
`

// nmapPrefixPaths lists where nmap's bundled MAC-prefix database
// (~49k IEEE OUIs) typically lives. We reuse it so vendor resolution matches
// what nmap itself reports, without bundling our own copy.
var nmapPrefixPaths = []string{
	"/opt/homebrew/share/nmap/nmap-mac-prefixes", // Homebrew (Apple Silicon)
	"/usr/local/share/nmap/nmap-mac-prefixes",    // Homebrew (Intel) / source
	"/usr/share/nmap/nmap-mac-prefixes",          // Linux distros
	"/opt/local/share/nmap/nmap-mac-prefixes",    // MacPorts
}

var (
	defaultOnce sync.Once
	defaultDB   DB
)

// LoadDefault returns the OUI database, preferring (in order): a user override
// at ~/.ndscan/oui.txt, nmap's bundled prefix file, then a tiny built-in
// sample. The parser handles both "AABBCC Vendor" and "AA:BB:CC\tVendor" forms.
func LoadDefault() DB {
	defaultOnce.Do(func() { defaultDB = loadDefault() })
	return defaultDB
}

func loadDefault() DB {
	home := userenv.Home()
	if b, err := os.ReadFile(filepath.Join(home, ".ndscan", "oui.txt")); err == nil {
		return parse(bytes.NewReader(b))
	}
	for _, path := range nmapPrefixDBPaths() {
		if b, err := os.ReadFile(path); err == nil {
			return parse(bytes.NewReader(b))
		}
	}
	return parse(strings.NewReader(sample))
}

// nmapPrefixDBPaths returns candidate locations, asking nmap where its data
// lives first (handles non-standard install prefixes), then the known paths.
func nmapPrefixDBPaths() []string {
	paths := append([]string(nil), nmapPrefixPaths...)
	if dir := nmapDataDir(); dir != "" {
		paths = append([]string{filepath.Join(dir, "nmap-mac-prefixes")}, paths...)
	}
	return paths
}

// nmapDataDir parses `nmap --version` for its compiled-in data directory.
func nmapDataDir() string {
	name := "nmap"
	if path := os.Getenv("NDSCAN_NMAP_PATH"); path != "" {
		name = path
	}
	out, err := exec.Command(name, "--version").Output()
	if err != nil {
		return ""
	}
	for _, ln := range strings.Split(string(out), "\n") {
		// e.g. "Compiled with: ... Nmap data dir: /opt/homebrew/share/nmap"
		if i := strings.Index(ln, "data dir:"); i >= 0 {
			return strings.TrimSpace(ln[i+len("data dir:"):])
		}
	}
	return ""
}

func parse(r io.Reader) DB {
	out := DB{}
	b, _ := io.ReadAll(r)
	for _, ln := range strings.Split(string(b), "\n") {
		ln = strings.TrimSpace(ln)
		if ln == "" || strings.HasPrefix(ln, "#") {
			continue
		}
		parts := strings.Fields(ln)
		if len(parts) >= 2 {
			k := norm(parts[0])
			if k != "" {
				out[k] = strings.Join(parts[1:], " ")
			}
			continue
		}
		if strings.Contains(ln, "\t") {
			p := strings.SplitN(ln, "\t", 2)
			k := norm(p[0])
			if k != "" {
				out[k] = strings.TrimSpace(p[1])
			}
		}
	}
	return out
}

func norm(s string) string {
	s = strings.ToUpper(strings.TrimSpace(s))
	for _, sep := range []string{":", "-", ".", "0X"} {
		s = strings.ReplaceAll(s, sep, "")
	}
	if len(s) < 6 {
		return ""
	}
	return s[:6]
}

func Lookup(db DB, mac string, fallback string) string {
	if mac == "" {
		return fallback
	}
	k := norm(mac)
	if v, ok := db[k]; ok {
		return v
	}
	return fallback
}
