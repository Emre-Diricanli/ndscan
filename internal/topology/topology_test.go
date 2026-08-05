package topology

import (
	"testing"

	"github.com/Emre-Diricanli/ndscan/internal/netinfo"
	"github.com/Emre-Diricanli/ndscan/internal/ui"
)

func row(ip string, ports ...ui.PortInfo) ui.Row {
	return ui.Row{IP: ip, Up: true, PortDetails: ports}
}

var homeLAN = []netinfo.Network{
	{Interface: "en0", CIDR: "192.168.1.0/24", Addr: "192.168.1.250"},
}

func TestBuild_PlacesHostsOnAttachedNetwork(t *testing.T) {
	rows := []ui.Row{row("192.168.1.10"), row("192.168.1.1"), row("192.168.1.250")}
	m := Build(rows, homeLAN, netinfo.Gateway{IP: "192.168.1.1", Interface: "en0"})

	if len(m.Segments) != 1 {
		t.Fatalf("want 1 segment, got %d (%+v)", len(m.Segments), m.Segments)
	}
	s := m.Segments[0]
	if s.CIDR != "192.168.1.0/24" || s.Interface != "en0" {
		t.Errorf("segment = %q/%q", s.CIDR, s.Interface)
	}
	if s.NotScanned {
		t.Error("segment with hosts must not be marked NotScanned")
	}
	if s.HostCount() != 3 {
		t.Fatalf("want 3 hosts, got %d", s.HostCount())
	}
	// Gateway sorts first so it can anchor the drawing.
	if !s.Nodes[0].IsGateway || s.Nodes[0].Row.IP != "192.168.1.1" {
		t.Errorf("first node = %+v, want the gateway", s.Nodes[0])
	}
	// This machine is flagged.
	var self *Node
	for i := range s.Nodes {
		if s.Nodes[i].Row.IP == "192.168.1.250" {
			self = &s.Nodes[i]
		}
	}
	if self == nil || !self.IsSelf {
		t.Errorf("192.168.1.250 should be flagged IsSelf: %+v", self)
	}
}

// An attached network with no scanned hosts must say so, not render as empty.
func TestBuild_UnscannedNetworkIsMarked(t *testing.T) {
	locals := append([]netinfo.Network{}, homeLAN...)
	locals = append(locals, netinfo.Network{
		Interface: "utun8", CIDR: "100.64.0.0/10", Addr: "100.127.245.23",
	})
	m := Build([]ui.Row{row("192.168.1.10")}, locals, netinfo.Gateway{})

	if len(m.Segments) != 2 {
		t.Fatalf("want 2 segments, got %d", len(m.Segments))
	}
	if m.Segments[0].NotScanned {
		t.Error("scanned segment marked NotScanned")
	}
	if !m.Segments[1].NotScanned {
		t.Error("VPN segment with no hosts must be marked NotScanned")
	}
	if m.Segments[1].HostCount() != 0 {
		t.Errorf("unscanned segment should have no hosts, got %d", m.Segments[1].HostCount())
	}
}

// Hosts outside every local network (e.g. a remote SSH scan) must still be
// grouped into a network rather than dropped or misattached.
func TestBuild_OrphansGroupedBySubnet(t *testing.T) {
	rows := []ui.Row{row("10.0.5.7"), row("10.0.5.9"), row("172.16.3.1")}
	m := Build(rows, homeLAN, netinfo.Gateway{})

	if len(m.Orphans) != 0 {
		t.Errorf("orphans should be folded into segments, got %d", len(m.Orphans))
	}
	var found10, found172 *Segment
	for i := range m.Segments {
		switch m.Segments[i].CIDR {
		case "10.0.5.0/24":
			found10 = &m.Segments[i]
		case "172.16.3.0/24":
			found172 = &m.Segments[i]
		}
	}
	if found10 == nil || found10.HostCount() != 2 {
		t.Errorf("10.0.5.0/24 segment = %+v, want 2 hosts", found10)
	}
	if found172 == nil || found172.HostCount() != 1 {
		t.Errorf("172.16.3.0/24 segment = %+v, want 1 host", found172)
	}
}

// Hosts on a sibling VLAN (reached through the gateway) must be tagged with the
// gateway they transited, and must not be treated as attached.
func TestBuild_RoutedSubnetTaggedViaGateway(t *testing.T) {
	rows := []ui.Row{
		row("192.168.1.10"),   // on the attached LAN
		row("192.168.100.50"), // sibling VLAN, reached via the gateway
		row("192.168.100.60"),
	}
	gw := netinfo.Gateway{IP: "192.168.1.1", Interface: "en0"}
	m := Build(rows, homeLAN, gw)

	var attached, routed *Segment
	for i := range m.Segments {
		switch m.Segments[i].CIDR {
		case "192.168.1.0/24":
			attached = &m.Segments[i]
		case "192.168.100.0/24":
			routed = &m.Segments[i]
		}
	}
	if attached == nil || !attached.Attached() {
		t.Fatalf("192.168.1.0/24 should be attached: %+v", attached)
	}
	if attached.RoutedVia != "" {
		t.Errorf("attached network must not be RoutedVia: %q", attached.RoutedVia)
	}
	if routed == nil {
		t.Fatalf("192.168.100.0/24 routed segment missing: %+v", m.Segments)
	}
	if routed.Attached() {
		t.Errorf("routed VLAN must not report Attached()")
	}
	if routed.RoutedVia != "192.168.1.1" {
		t.Errorf("routed VLAN RoutedVia = %q, want 192.168.1.1", routed.RoutedVia)
	}
	if routed.HostCount() != 2 {
		t.Errorf("routed VLAN host count = %d, want 2", routed.HostCount())
	}
}

// Without a known gateway, routed hosts still segment but carry no via label
// (we can't claim a path we don't know).
func TestBuild_RoutedWithoutGatewayHasNoVia(t *testing.T) {
	m := Build([]ui.Row{row("10.9.9.9")}, homeLAN, netinfo.Gateway{})
	for i := range m.Segments {
		if m.Segments[i].CIDR == "10.9.9.0/24" && m.Segments[i].RoutedVia != "" {
			t.Errorf("no gateway known, but RoutedVia = %q", m.Segments[i].RoutedVia)
		}
	}
}

func TestBuild_SeverityRollup(t *testing.T) {
	rows := []ui.Row{
		row("192.168.1.10", ui.PortInfo{Port: 22, Severity: "info"}, ui.PortInfo{Port: 23, Severity: "high"}),
		row("192.168.1.11", ui.PortInfo{Port: 80, Severity: ""}),
		row("192.168.1.12"),
	}
	m := Build(rows, homeLAN, netinfo.Gateway{})
	got := map[string]string{}
	for _, n := range m.Segments[0].Nodes {
		got[n.Row.IP] = n.Severity
	}
	if got["192.168.1.10"] != "high" {
		t.Errorf("worst severity = %q, want high", got["192.168.1.10"])
	}
	if got["192.168.1.11"] != "" || got["192.168.1.12"] != "" {
		t.Errorf("unremarkable hosts should have no severity: %+v", got)
	}
}

func TestBuild_NodesSortedNumerically(t *testing.T) {
	rows := []ui.Row{row("192.168.1.100"), row("192.168.1.9"), row("192.168.1.10")}
	m := Build(rows, homeLAN, netinfo.Gateway{})
	want := []string{"192.168.1.9", "192.168.1.10", "192.168.1.100"}
	for i, w := range want {
		if got := m.Segments[0].Nodes[i].Row.IP; got != w {
			t.Fatalf("node %d = %q, want %q (numeric order)", i, got, w)
		}
	}
}

func TestBuild_EmptyInputs(t *testing.T) {
	m := Build(nil, nil, netinfo.Gateway{})
	if len(m.Segments) != 0 || len(m.Orphans) != 0 {
		t.Errorf("empty build should yield nothing, got %+v", m)
	}
	// Locals with no scan still produce segments, all marked unscanned.
	m = Build(nil, homeLAN, netinfo.Gateway{})
	if len(m.Segments) != 1 || !m.Segments[0].NotScanned {
		t.Errorf("want 1 unscanned segment, got %+v", m.Segments)
	}
}
