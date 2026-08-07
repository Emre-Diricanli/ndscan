package alert

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

// Missing and invalid are different states: missing means a fresh install and
// gets Defaults; invalid is refused, because substituting Defaults would
// silently re-enable rules the user deliberately disabled. An empty list sits
// in between — it looks exactly like a truncated write, so it still degrades
// to Defaults.
func TestLoadStates(t *testing.T) {
	valid := []byte(`[{"name":"telnet-watch","kind":"port-opened","ports":[23]}]`)
	cases := []struct {
		name         string
		contents     []byte // nil = file absent
		wantErr      bool
		wantDefaults bool
	}{
		{"missing file", nil, false, true},
		{"invalid file", []byte("{not json"), true, false},
		{"empty file", []byte(""), true, false},
		{"empty list", []byte("[]"), false, true},
		{"valid file", valid, false, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			t.Setenv("NDSCAN_CONFIG_DIR", dir)
			if tc.contents != nil {
				if err := os.WriteFile(filepath.Join(dir, "rules.json"), tc.contents, 0o644); err != nil {
					t.Fatal(err)
				}
			}
			got, err := LoadChecked()
			if (err != nil) != tc.wantErr {
				t.Fatalf("LoadChecked() error = %v, wantErr %v", err, tc.wantErr)
			}
			if tc.wantDefaults && !reflect.DeepEqual(got, Defaults()) {
				t.Errorf("LoadChecked() = %+v, want Defaults", got)
			}
			if tc.wantDefaults && len(got) == 0 {
				t.Error("defaults must not be empty: a fresh install should do something useful")
			}
			if !tc.wantErr && !tc.wantDefaults && len(got) == 0 {
				t.Error("LoadChecked() of a valid file returned no rules")
			}

			plain := Load()
			switch {
			case tc.wantErr:
				// The non-erroring form must never substitute Defaults for a
				// file the user edited: that silently re-enables rules they
				// turned off. Refusing (no rules) is the honest failure.
				if reflect.DeepEqual(plain, Defaults()) {
					t.Error("Load() substituted Defaults for an invalid file")
				}
			case !reflect.DeepEqual(plain, got):
				t.Errorf("Load() = %+v, want the LoadChecked result %+v", plain, got)
			}
		})
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
