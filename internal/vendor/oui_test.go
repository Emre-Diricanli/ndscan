package vendor

import "strings"

import "testing"

func TestParseBothFormats(t *testing.T) {
	db := parse(strings.NewReader("B06A41 Google\n00:25:96\tD-Link\n# comment\n\n"))
	if v := Lookup(db, "b0:6a:41:9e:2e:32", ""); v != "Google" {
		t.Errorf("space format: got %q", v)
	}
	if v := Lookup(db, "00:25:96:11:22:33", ""); v != "D-Link" {
		t.Errorf("tab format: got %q", v)
	}
	if v := Lookup(db, "ff:ff:ff:00:00:00", "none"); v != "none" {
		t.Errorf("unknown should return fallback, got %q", v)
	}
}

func TestLoadDefaultUsesNmapDB(t *testing.T) {
	db := LoadDefault()
	// If nmap's prefix DB is present, it has tens of thousands of entries and
	// resolves common OUIs; otherwise we fall back to the 4-entry sample.
	if len(db) < 100 {
		t.Skipf("nmap prefix DB not found (got %d entries) — fallback in use", len(db))
	}
	if v := Lookup(db, "b0:6a:41:00:00:00", ""); v == "" {
		t.Error("expected a vendor for a well-known Google OUI")
	}
}
