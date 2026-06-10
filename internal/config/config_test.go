package config

import (
	"reflect"
	"testing"
)

func TestProfilesCRUDAndLast(t *testing.T) {
	t.Setenv("NDSCAN_CONFIG_DIR", t.TempDir())

	if got := Load(); got.Last != nil || len(got.Profiles) != 0 {
		t.Fatalf("expected empty config, got %+v", got)
	}

	s := Settings{Targets: "192.168.1.0/24", Preset: "quick", ShowMac: true}
	if err := SaveLast(s); err != nil {
		t.Fatal(err)
	}
	if err := UpsertProfile("home", s); err != nil {
		t.Fatal(err)
	}
	s2 := s
	s2.Preset = "deep"
	if err := UpsertProfile("home", s2); err != nil { // replace, not duplicate
		t.Fatal(err)
	}
	if err := UpsertProfile("office", Settings{Targets: "10.0.0.0/24"}); err != nil {
		t.Fatal(err)
	}

	f := Load()
	if f.Last == nil || f.Last.Targets != "192.168.1.0/24" {
		t.Fatalf("last settings not persisted: %+v", f.Last)
	}
	if len(f.Profiles) != 2 {
		t.Fatalf("want 2 profiles, got %d", len(f.Profiles))
	}
	if f.Profiles[0].Name != "home" || f.Profiles[0].Settings.Preset != "deep" {
		t.Fatalf("upsert did not replace: %+v", f.Profiles[0])
	}

	if err := DeleteProfile("home"); err != nil {
		t.Fatal(err)
	}
	if f = Load(); len(f.Profiles) != 1 || f.Profiles[0].Name != "office" {
		t.Fatalf("delete failed: %+v", f.Profiles)
	}
}

func TestHistoryAndDiff(t *testing.T) {
	t.Setenv("NDSCAN_CONFIG_DIR", t.TempDir())

	targets := []string{"192.168.1.0/24"}
	if got := LoadHistory(targets, "", "quick"); got != nil {
		t.Fatalf("expected nil history, got %v", got)
	}

	prev := []HostSnapshot{
		{IP: "192.168.1.1", Ports: []string{"80/tcp http", "53/udp dns"}},
		{IP: "192.168.1.5", Ports: []string{"22/tcp ssh"}},
	}
	if err := SaveHistory(targets, "", "quick", prev); err != nil {
		t.Fatal(err)
	}
	if got := LoadHistory(targets, "", "quick"); !reflect.DeepEqual(got, prev) {
		t.Fatalf("history roundtrip mismatch: %v vs %v", got, prev)
	}
	// different signature -> separate history
	if got := LoadHistory(targets, "22", "quick"); got != nil {
		t.Fatalf("ports should change the history key")
	}

	cur := []HostSnapshot{
		{IP: "192.168.1.1", Ports: []string{"80/tcp http", "443/tcp https"}}, // +443 -53
		{IP: "192.168.1.9", Ports: []string{"22/tcp ssh"}},                   // new host
		// .5 is gone
	}
	d := Diff(prev, cur)
	if !d["192.168.1.9"].New {
		t.Errorf(".9 should be NEW: %+v", d["192.168.1.9"])
	}
	if !d["192.168.1.5"].Gone {
		t.Errorf(".5 should be GONE: %+v", d["192.168.1.5"])
	}
	r1 := d["192.168.1.1"]
	if !reflect.DeepEqual(r1.PortsOpened, []string{"443"}) || !reflect.DeepEqual(r1.PortsClosed, []string{"53"}) {
		t.Errorf(".1 diff wrong: %+v", r1)
	}

	// no change -> empty diff map
	if d := Diff(cur, cur); len(d) != 0 {
		t.Errorf("identical scans should produce empty diff, got %v", d)
	}
	// first scan -> nil
	if d := Diff(nil, cur); d != nil {
		t.Errorf("nil prev should produce nil diff")
	}
}
