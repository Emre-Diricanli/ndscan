package web

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/Emre-Diricanli/ndscan/internal/topology"
	"github.com/Emre-Diricanli/ndscan/internal/ui"
)

// Inferred must survive the trip to the wire in both directions: a guessed
// boundary that arrives as "inferred":false would render as a measured fact.
func TestSegmentDTO_CarriesInferred(t *testing.T) {
	cases := []struct {
		name     string
		inferred bool
		want     string
	}{
		{"guessed boundary", true, `"inferred":true`},
		{"observed boundary", false, `"inferred":false`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := topology.Map{Segments: []topology.Segment{{
				CIDR: "192.0.2.0/24", Inferred: tc.inferred,
			}}}
			b, err := json.Marshal(toTopologyDTO(m))
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(string(b), tc.want) {
				t.Errorf("JSON missing %s: %s", tc.want, b)
			}

			// Round-trip: decode what the browser would receive.
			var got topologyDTO
			if err := json.Unmarshal(b, &got); err != nil {
				t.Fatal(err)
			}
			if got.Segments[0].Inferred != tc.inferred {
				t.Errorf("round-tripped Inferred = %v, want %v", got.Segments[0].Inferred, tc.inferred)
			}
		})
	}
}

// Orphans answered the scan, so they must appear in the DTO; but a map with
// no orphans must not emit an empty section for them.
func TestTopologyDTO_Orphans(t *testing.T) {
	cases := []struct {
		name        string
		orphans     []topology.Node
		wantKey     bool
		wantContain string
	}{
		{
			name: "orphans are surfaced",
			orphans: []topology.Node{
				{Row: ui.Row{IP: "203.0.113.10", Host: "vps", Up: true}, Severity: "info"},
			},
			wantKey:     true,
			wantContain: `"ip":"203.0.113.10"`,
		},
		{name: "no orphans, no section", orphans: nil, wantKey: false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := topology.Map{Orphans: tc.orphans}
			b, err := json.Marshal(toTopologyDTO(m))
			if err != nil {
				t.Fatal(err)
			}
			js := string(b)
			if got := strings.Contains(js, `"orphans"`); got != tc.wantKey {
				t.Errorf("orphans key present = %v, want %v: %s", got, tc.wantKey, js)
			}
			if tc.wantContain != "" && !strings.Contains(js, tc.wantContain) {
				t.Errorf("JSON missing %s: %s", tc.wantContain, js)
			}
		})
	}
}

// Regression guard on the wire contract: the exact JSON for a fixed map locks
// every existing field's name, spelling, and position, so a rename or a type
// change cannot slip through as "additive".
func TestToTopologyDTO_ExistingFieldsUnchanged(t *testing.T) {
	m := topology.Map{
		Gateway: "192.0.2.1",
		Segments: []topology.Segment{{
			CIDR: "192.0.2.0/24", Interface: "en0", SelfAddr: "192.0.2.5",
			NotScanned: false, RoutedVia: "192.0.2.1",
			Nodes: []topology.Node{{
				Row:      ui.Row{IP: "192.0.2.10", Host: "printer", Up: true, RTT: "2ms"},
				Severity: "info",
			}},
		}},
	}
	b, err := json.Marshal(toTopologyDTO(m))
	if err != nil {
		t.Fatal(err)
	}
	want := `{"gateway":"192.0.2.1","segments":[{"cidr":"192.0.2.0/24","interface":"en0","selfAddr":"192.0.2.5",` +
		`"inferred":false,"notScanned":false,"routedVia":"192.0.2.1","nodes":[{"isGateway":false,"isSelf":false,` +
		`"severity":"info","host":{"ip":"192.0.2.10","hostname":"printer","rtt":"2ms","up":true}}]}]}`
	if string(b) != want {
		t.Errorf("contract drift:\n got: %s\nwant: %s", b, want)
	}
}
