package vendor

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"
)

type DB map[string]string

const sample = `00:11:22	AcmeCorp
00:25:96	D-Link
3C:5A:B4	TP-Link
48:5A:3F	Cisco
`

func LoadDefault() DB {
	home, _ := os.UserHomeDir()
	path := filepath.Join(home, ".ndscan", "oui.txt")
	if b, err := os.ReadFile(path); err == nil {
		return parse(bytes.NewReader(b))
	}
	return parse(strings.NewReader(sample))
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
