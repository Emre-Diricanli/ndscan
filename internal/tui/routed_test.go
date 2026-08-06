package tui

import (
	"strings"
	"testing"

	"github.com/Emre-Diricanli/ndscan/internal/netinfo"
	"github.com/Emre-Diricanli/ndscan/internal/ui"
)

// routedModel is a results-screen model on 192.168.2.0/24 with a gateway.
func routedModel(t *testing.T, rows ...ui.Row) Model {
	t.Helper()
	t.Setenv("NDSCAN_CONFIG_DIR", t.TempDir())
	m := New("test")
	m.width, m.height = 100, 40
	m.screen = screenResults
	m.netLocals = []netinfo.Network{{Interface: "en0", CIDR: "192.168.2.0/24", Addr: "192.168.2.157"}}
	m.netGateway = netinfo.Gateway{IP: "192.168.2.1", Interface: "en0"}
	m.view = viewTopology
	m.rows = rows
	m.rebuildTable()
	return m
}

// A routed VLAN host must render nested and labeled "via <gateway>", visibly
// distinct from an attached network.
func TestTopologyView_RoutedSegmentLabeledVia(t *testing.T) {
	m := routedModel(t,
		ui.Row{IP: "192.168.2.10", Host: "nas", Up: true},
		ui.Row{IP: "192.168.100.50", Host: "nvr", Up: true},
	)
	out := m.topologyView()

	if !strings.Contains(out, "192.168.100.0/24") {
		t.Errorf("routed VLAN missing from map:\n%s", out)
	}
	if !strings.Contains(out, "via 192.168.2.1") {
		t.Errorf("routed segment must be labeled 'via <gateway>':\n%s", out)
	}
	if !strings.Contains(out, glyphRouted) {
		t.Errorf("routed glyph missing:\n%s", out)
	}
}

// startRoutedSweep must target the attached network plus the sibling
// candidates, and it must include an explicitly-named VLAN from the form.
func TestStartRoutedSweep_TargetsSiblingsPlusExplicit(t *testing.T) {
	m := routedModel(t, ui.Row{IP: "192.168.2.10", Up: true})
	m.targetsIn.SetValue("192.168.2.0/24 192.168.177.0/24") // name an odd VLAN

	next, cmd := m.startRoutedSweep()
	nm := next.(Model)
	if cmd == nil {
		t.Fatal("sweep should start a scan (nil cmd)")
	}
	if !nm.routedSweep {
		t.Error("routedSweep flag should be set while the sweep runs")
	}
	if nm.screen != screenRunning {
		t.Errorf("screen = %v, want running", nm.screen)
	}

	targets := strings.Join(nm.params.targets, " ")
	// The attached network is included so existing hosts stay on the map.
	if !strings.Contains(targets, "192.168.2.0/24") {
		t.Errorf("sweep should include the attached network: %v", nm.params.targets)
	}
	// A common sibling and the explicitly named one must both be probed.
	if !strings.Contains(targets, "192.168.100.0/24") {
		t.Errorf("sweep should include common sibling .100: %v", nm.params.targets)
	}
	if !strings.Contains(targets, "192.168.177.0/24") {
		t.Errorf("sweep should include explicitly-named .177: %v", nm.params.targets)
	}
}

// With no attached IPv4 network there is nothing to derive siblings from; the
// sweep must decline with a notice rather than start an empty scan.
func TestStartRoutedSweep_NoCandidatesLeavesNotice(t *testing.T) {
	t.Setenv("NDSCAN_CONFIG_DIR", t.TempDir())
	m := New("test")
	m.width, m.height = 100, 40
	m.screen = screenResults
	m.view = viewTopology
	m.netLocals = []netinfo.Network{{Interface: "utun8", CIDR: "100.127.245.23/32", Addr: "100.127.245.23"}}
	// The sweep re-reads the interface table, so pin it to this machine's
	// stubbed networks rather than whatever the test host really has.
	m.localsFn = func() []netinfo.Network { return m.netLocals }
	m.targetsIn.SetValue("") // New() prefills the real local CIDR; clear it
	m.rebuildTable()

	next, cmd := m.startRoutedSweep()
	nm := next.(Model)
	if cmd != nil {
		t.Error("no candidates should mean no scan starts")
	}
	if nm.routedSweep {
		t.Error("routedSweep must not be set when nothing is probed")
	}
	if nm.notice == "" {
		t.Error("expected a notice explaining why nothing was swept")
	}
}

// routedHostCount counts only hosts on non-attached segments.
func TestRoutedHostCount(t *testing.T) {
	m := routedModel(t,
		ui.Row{IP: "192.168.2.10", Up: true},   // attached
		ui.Row{IP: "192.168.2.20", Up: true},   // attached
		ui.Row{IP: "192.168.100.50", Up: true}, // routed
		ui.Row{IP: "10.9.9.9", Up: true},       // routed (different subnet)
	)
	if got := m.routedHostCount(); got != 2 {
		t.Errorf("routedHostCount = %d, want 2 (only non-attached)", got)
	}
}

// The S key triggers the sweep only in map view.
func TestSKey_TriggersSweepOnlyInMap(t *testing.T) {
	m := routedModel(t, ui.Row{IP: "192.168.2.10", Up: true})

	// In map view, S starts a sweep.
	next, _ := m.updateResults(keyRunes("S"))
	if !next.(Model).routedSweep {
		t.Error("S in map view should start a routed sweep")
	}

	// In table view, S does nothing (no sweep, no crash).
	m.view = viewTable
	next, _ = m.updateResults(keyRunes("S"))
	if next.(Model).routedSweep {
		t.Error("S outside the map must not start a sweep")
	}
}

// A TUI left open across a Wi-Fi change must sweep the network it is on now,
// not the one it started on. Deriving candidates from the startup snapshot
// would probe a neighbourhood the machine already left.
func TestStartRoutedSweep_RefreshesLocalsBeforeDerivingCandidates(t *testing.T) {
	m := routedModel(t, ui.Row{IP: "192.168.2.10", Up: true})
	m.netLocals = []netinfo.Network{{Interface: "en0", CIDR: "192.168.1.0/24", Addr: "192.168.1.50"}}
	// The machine has since moved to 192.168.9.x.
	m.localsFn = func() []netinfo.Network {
		return []netinfo.Network{{Interface: "en0", CIDR: "192.168.9.0/24", Addr: "192.168.9.50"}}
	}
	m.targetsIn.SetValue("")

	next, cmd := m.startRoutedSweep()
	if cmd == nil {
		t.Fatal("sweep should start")
	}
	got := next.(Model).params.targets
	if len(got) == 0 || got[0] != "192.168.9.0/24" {
		t.Errorf("targets = %v; the attached network must be the one we are on now", got)
	}
	// Candidates are derived around the *current* third octet, so .7/.8/.10/.11
	// appear only if the refresh took effect. (192.168.1.0/24 is deliberately
	// not asserted absent: it is a plausible sibling of .9 in its own right.)
	joined := strings.Join(got, " ")
	for _, want := range []string{"192.168.8.0/24", "192.168.10.0/24"} {
		if !strings.Contains(joined, want) {
			t.Errorf("targets %q missing %s — candidates were derived from the stale network", joined, want)
		}
	}
}
