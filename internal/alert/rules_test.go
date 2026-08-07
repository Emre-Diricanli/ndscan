package alert

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestLoadDefaultsWhenMissing(t *testing.T) {
	t.Setenv("NDSCAN_CONFIG_DIR", t.TempDir())

	got := Load()
	want := Defaults()
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("missing file should yield defaults\ngot:  %+v\nwant: %+v", got, want)
	}
	if len(got) == 0 {
		t.Fatal("defaults must not be empty: a fresh install should do something useful")
	}
}

func TestLoadCorruptFallsBackToDefaults(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("NDSCAN_CONFIG_DIR", dir)
	if err := os.WriteFile(filepath.Join(dir, "rules.json"), []byte("{not json"), 0o644); err != nil {
		t.Fatal(err)
	}

	if got := Load(); !reflect.DeepEqual(got, Defaults()) {
		t.Fatalf("corrupt file should yield defaults, got %+v", got)
	}
}

func TestLoadEmptyListFallsBackToDefaults(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("NDSCAN_CONFIG_DIR", dir)
	if err := os.WriteFile(filepath.Join(dir, "rules.json"), []byte("[]"), 0o644); err != nil {
		t.Fatal(err)
	}

	// An explicitly empty file would silence all alerting, which is exactly
	// what a corrupt/truncated write looks like — treat it as unusable.
	if got := Load(); !reflect.DeepEqual(got, Defaults()) {
		t.Fatalf("empty rule list should yield defaults, got %+v", got)
	}
}

func TestSaveLoadRoundTrip(t *testing.T) {
	t.Setenv("NDSCAN_CONFIG_DIR", t.TempDir())

	rules := []Rule{
		{Name: "telnet-watch", Kind: KindPortOpened, Ports: []int{23}, Severity: "high"},
		{Name: "quiet-printer", Kind: KindNewDevice, StableOnly: true, Ignore: []string{"mac:00:11:22:33:44:55"}},
	}
	if err := Save(rules); err != nil {
		t.Fatal(err)
	}
	got := Load()
	if !reflect.DeepEqual(got, rules) {
		t.Fatalf("round trip mismatch\ngot:  %+v\nwant: %+v", got, rules)
	}
}

func TestDefaultsAreWellFormed(t *testing.T) {
	kinds := map[string]bool{}
	for _, r := range Defaults() {
		if r.Name == "" {
			t.Errorf("default rule with empty name: %+v", r)
		}
		switch r.Kind {
		case KindNewDevice, KindPortOpened, KindHostGone, KindGatewayMACChanged:
			kinds[r.Kind] = true
		default:
			t.Errorf("default rule with unknown kind %q", r.Kind)
		}
	}
	for _, k := range []string{KindNewDevice, KindPortOpened, KindHostGone, KindGatewayMACChanged} {
		if !kinds[k] {
			t.Errorf("defaults do not cover kind %q", k)
		}
	}
}

func TestSeverityRankOrdering(t *testing.T) {
	// The ordering every sorter and threshold relies on.
	if !(severityRank("high") > severityRank("warn") &&
		severityRank("warn") > severityRank("info") &&
		severityRank("info") > severityRank("")) {
		t.Fatal("severity ranks out of order")
	}
}
