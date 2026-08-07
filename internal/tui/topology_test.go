package tui

import (
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/Emre-Diricanli/ndscan/internal/netinfo"
	"github.com/Emre-Diricanli/ndscan/internal/ui"
)

// mapModel builds a results-screen model with a known network layout.
func mapModel(t *testing.T, rows ...ui.Row) Model {
	t.Helper()
	t.Setenv("NDSCAN_CONFIG_DIR", t.TempDir())
	m := New("test")
	m.width, m.height = 100, 40
	m.screen = screenResults
	m.netLocals = []netinfo.Network{
		{Interface: "en0", CIDR: "192.168.1.0/24", Addr: "192.168.1.250"},
		{Interface: "utun8", CIDR: "100.64.0.0/10", Addr: "100.127.245.23"},
	}
	m.netGateway = netinfo.Gateway{IP: "192.168.1.1", Interface: "en0"}
	m.rows = rows
	m.rebuildTable()
	return m
}

func TestTopologyView_ShowsSegmentsAndGateway(t *testing.T) {
	m := mapModel(t,
		ui.Row{IP: "192.168.1.1", Host: "router", Up: true},
		ui.Row{IP: "192.168.1.10", Host: "nas", Up: true,
			PortDetails: []ui.PortInfo{{Port: 22, Severity: "info"}}},
	)
	out := m.topologyView()

	for _, want := range []string{"192.168.1.0/24", "en0", "router", "gateway", "nas", "scanned"} {
		if !strings.Contains(out, want) {
			t.Errorf("map missing %q:\n%s", want, out)
		}
	}
	// The gateway must carry its own glyph, not the plain host glyph.
	if !strings.Contains(out, glyphGateway) {
		t.Errorf("gateway glyph missing:\n%s", out)
	}
}

// An attached network with no scanned hosts must be shown as unscanned rather
// than omitted or rendered as if it were empty.
func TestTopologyView_MarksUnscannedNetwork(t *testing.T) {
	m := mapModel(t, ui.Row{IP: "192.168.1.10", Up: true})
	out := m.topologyView()

	if !strings.Contains(out, "100.64.0.0/10") {
		t.Errorf("VPN network missing from map:\n%s", out)
	}
	if !strings.Contains(out, "not scanned") {
		t.Errorf("unscanned network not labeled:\n%s", out)
	}
}

// The map is useful before any scan: it still lists attached networks.
func TestTopologyView_UsefulWithNoResults(t *testing.T) {
	m := mapModel(t)
	out := m.topologyView()
	if !strings.Contains(out, "192.168.1.0/24") || !strings.Contains(out, "100.64.0.0/10") {
		t.Errorf("empty-scan map should still list attached networks:\n%s", out)
	}
	if strings.Contains(out, "No networks detected") {
		t.Errorf("networks exist but map claims none:\n%s", out)
	}
}

// With no networks at all the map must say so plainly.
func TestTopologyView_NoNetworksMessage(t *testing.T) {
	t.Setenv("NDSCAN_CONFIG_DIR", t.TempDir())
	m := New("test")
	m.netLocals = nil
	m.netGateway = netinfo.Gateway{}
	if out := m.topologyView(); !strings.Contains(out, "No networks detected") {
		t.Errorf("want an explicit empty state, got:\n%s", out)
	}
}

func TestTopologyView_RiskIsSurfaced(t *testing.T) {
	m := mapModel(t, ui.Row{IP: "192.168.1.31", Up: true,
		PortDetails: []ui.PortInfo{{Port: 23, Service: "telnet", Severity: "high", Risk: "Telnet"}}})
	out := m.topologyView()
	if !strings.Contains(out, glyphRisk) {
		t.Errorf("high-severity host should carry the risk glyph:\n%s", out)
	}
}

// A host outside every local network is grouped by the target that covered it,
// not by a /24 invented around its address. With no target to place it in it
// stays an explicit unknown — the map no longer manufactures a plausible
// subnet nobody scanned.
func TestTopologyView_RemoteSubnetUsesScannedPrefix(t *testing.T) {
	m := mapModel(t, ui.Row{IP: "10.20.30.5", Host: "remote", Up: true})
	m.params.targets = []string{"10.20.0.0/16"}
	out := m.topologyView()
	if !strings.Contains(out, "10.20.0.0/16") {
		t.Errorf("routed host should render under the prefix that was scanned:\n%s", out)
	}
	if strings.Contains(out, "10.20.30.0/24") {
		t.Errorf("map invented a /24 that was never scanned:\n%s", out)
	}
}

func TestShortAddr(t *testing.T) {
	cases := []struct{ ip, cidr, want string }{
		{"192.168.1.10", "192.168.1.0/24", ".10"},
		{"192.168.1.250", "192.168.1.0/24", ".250"},
		// Outside the segment's /24 prefix: show the full address.
		{"10.0.0.1", "192.168.1.0/24", "10.0.0.1"},
		{"192.168.1.10", "malformed", "192.168.1.10"},
	}
	for _, c := range cases {
		if got := shortAddr(c.ip, c.cidr); got != c.want {
			t.Errorf("shortAddr(%q,%q) = %q, want %q", c.ip, c.cidr, got, c.want)
		}
	}
}

func TestPortSummary_TruncatesWithOverflowMarker(t *testing.T) {
	r := ui.Row{PortDetails: []ui.PortInfo{
		{Port: 22}, {Port: 80}, {Port: 443}, {Port: 5000}, {Port: 8080}, {Port: 9000},
	}}
	got := portSummary(r)
	if !strings.HasSuffix(got, "+2") {
		t.Errorf("portSummary = %q, want a +2 overflow marker", got)
	}
	if strings.Contains(got, "9000") {
		t.Errorf("portSummary should not list beyond the cap: %q", got)
	}
	if portSummary(ui.Row{}) != "" {
		t.Errorf("no ports should render empty")
	}
}

// Pressing "t" must cycle table → tree → map → table.
func TestViewCyclesThroughMap(t *testing.T) {
	m := mapModel(t, ui.Row{IP: "192.168.1.10", Up: true})
	if m.view != viewTable {
		t.Fatalf("initial view = %v, want table", m.view)
	}
	press := func(mm Model) Model {
		next, _ := mm.updateResults(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("t")})
		return next.(Model)
	}
	m = press(m)
	if m.view != viewTree {
		t.Fatalf("after 1 press = %v, want tree", m.view)
	}
	m = press(m)
	if m.view != viewTopology {
		t.Fatalf("after 2 presses = %v, want map", m.view)
	}
	m = press(m)
	if m.view != viewTable {
		t.Fatalf("after 3 presses = %v, want table again", m.view)
	}
}

// A /32 tunnel endpoint is not a scannable range: the map must say so, and "s"
// must not offer it.
func TestTopologyView_PointToPointNotOfferedForScan(t *testing.T) {
	t.Setenv("NDSCAN_CONFIG_DIR", t.TempDir())
	m := New("test")
	m.width, m.height = 100, 40
	m.screen = screenResults
	m.netLocals = []netinfo.Network{
		{Interface: "utun8", CIDR: "100.127.245.23/32", Addr: "100.127.245.23"},
	}
	m.rebuildTable()

	out := m.topologyView()
	if !strings.Contains(out, "point-to-point") {
		t.Errorf("/32 should be labeled point-to-point:\n%s", out)
	}
	if strings.Contains(out, "to scan this network") {
		t.Errorf("/32 must not advertise a scan:\n%s", out)
	}
	if cidr, ok := m.firstUnscannedNetwork(); ok {
		t.Errorf("firstUnscannedNetwork offered %q, want none", cidr)
	}
}

// With a real scannable network present, "s" should offer it.
func TestFirstUnscannedNetwork_OffersRealRange(t *testing.T) {
	m := mapModel(t, ui.Row{IP: "192.168.1.10", Up: true})
	cidr, ok := m.firstUnscannedNetwork()
	if !ok || cidr != "100.64.0.0/10" {
		t.Errorf("firstUnscannedNetwork = %q/%v, want 100.64.0.0/10", cidr, ok)
	}
}

func TestResultViewString(t *testing.T) {
	if viewTable.String() != "table" || viewTree.String() != "tree" || viewTopology.String() != "map" {
		t.Errorf("view names = %q/%q/%q", viewTable, viewTree, viewTopology)
	}
}
