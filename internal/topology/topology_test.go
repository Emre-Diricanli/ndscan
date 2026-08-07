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
	m := Build(rows, Input{Locals: homeLAN, Gateway: netinfo.Gateway{IP: "192.168.1.1", Interface: "en0"}})

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
	m := Build([]ui.Row{row("192.168.1.10")}, Input{Locals: locals, Gateway: netinfo.Gateway{}})

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

func TestBuild_PrefixPlacement(t *testing.T) {
	tests := []struct {
		name      string
		locals    []netinfo.Network
		rows      []ui.Row
		wantIface string
		wantSelf  bool
		wantHosts int
	}{
		{
			name: "longest prefix beats earlier VPN",
			locals: []netinfo.Network{
				{Interface: "utun8", CIDR: "192.168.0.0/16", Addr: "192.168.50.1"},
				{Interface: "en0", CIDR: "192.168.2.0/24", Addr: "192.168.2.10"},
			},
			wantIface: "en0",
			wantSelf:  true,
			rows:      []ui.Row{row("192.168.2.10"), row("192.168.2.99")},
			wantHosts: 2,
		},
		{
			name: "equal prefixes preserve interface order",
			locals: []netinfo.Network{
				{Interface: "first", CIDR: "192.168.2.0/24", Addr: "192.168.2.10"},
				{Interface: "second", CIDR: "192.168.2.0/24", Addr: "192.168.2.11"},
			},
			wantIface: "first",
			wantSelf:  true,
			rows:      []ui.Row{row("192.168.2.10")},
			wantHosts: 1,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := Build(tt.rows, Input{Locals: tt.locals})
			for _, segment := range m.Segments {
				if segment.HostCount() > 0 {
					if segment.Interface != tt.wantIface || segment.Nodes[0].IsSelf != tt.wantSelf {
						t.Fatalf("host placed on %q (self=%v), want %q (self=%v)", segment.Interface, segment.Nodes[0].IsSelf, tt.wantIface, tt.wantSelf)
					}
					if segment.HostCount() != tt.wantHosts {
						t.Fatalf("hosts on %q = %d, want %d", segment.Interface, segment.HostCount(), tt.wantHosts)
					}
					return
				}
			}
			t.Fatalf("host was not placed: %+v", m)
		})
	}
}

func TestBuild_CoveragePlacement(t *testing.T) {
	tests := []struct {
		name        string
		rows        []ui.Row
		coverage    []string
		wantCIDRs   []string
		wantOrphans int
	}{
		{name: "one slash sixteen", rows: []ui.Row{row("10.20.1.1"), row("10.20.200.2")}, coverage: []string{"10.20.0.0/16"}, wantCIDRs: []string{"10.20.0.0/16"}},
		{name: "bare address stays host observation", rows: []ui.Row{row("10.9.9.9")}, coverage: []string{"10.9.9.9"}, wantCIDRs: []string{"10.9.9.9/32"}},
		{name: "most specific coverage", rows: []ui.Row{row("10.20.2.3")}, coverage: []string{"10.20.0.0/16", "10.20.2.0/24"}, wantCIDRs: []string{"10.20.2.0/24"}},
		{name: "IPv6 coverage", rows: []ui.Row{row("2001:db8:abcd::7")}, coverage: []string{"2001:db8:abcd::/48"}, wantCIDRs: []string{"2001:db8:abcd::/48"}},
		{name: "segments sort independently of map iteration", rows: []ui.Row{row("172.16.0.1"), row("10.0.0.1")}, coverage: []string{"172.16.0.0/16", "10.0.0.0/8"}, wantCIDRs: []string{"10.0.0.0/8", "172.16.0.0/16"}},
		{name: "outside coverage remains orphan", rows: []ui.Row{row("172.16.3.1")}, coverage: []string{"10.20.0.0/16"}, wantOrphans: 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := Build(tt.rows, Input{Locals: homeLAN, Gateway: netinfo.Gateway{IP: "192.168.1.1"}, Coverage: tt.coverage})
			var got []string
			for _, segment := range m.Segments[1:] {
				got = append(got, segment.CIDR)
				if segment.RoutedVia != "" {
					t.Errorf("coverage does not prove RoutedVia, got %q", segment.RoutedVia)
				}
				if segment.Inferred {
					t.Errorf("scan target %q was incorrectly marked inferred", segment.CIDR)
				}
			}
			if len(got) != len(tt.wantCIDRs) {
				t.Fatalf("routed CIDRs = %v, want %v", got, tt.wantCIDRs)
			}
			for i := range got {
				if got[i] != tt.wantCIDRs[i] {
					t.Errorf("routed CIDR %d = %q, want %q", i, got[i], tt.wantCIDRs[i])
				}
			}
			if len(m.Orphans) != tt.wantOrphans {
				t.Errorf("orphans = %d, want %d", len(m.Orphans), tt.wantOrphans)
			}
		})
	}
}

func TestBuild_ScannedEmptyDiffersFromNeverScanned(t *testing.T) {
	locals := []netinfo.Network{
		{Interface: "en0", CIDR: "192.168.1.0/24", Addr: "192.168.1.10"},
		{Interface: "en1", CIDR: "192.168.2.0/24", Addr: "192.168.2.10"},
	}
	m := Build(nil, Input{Locals: locals, Coverage: []string{"192.168.1.0/24"}})
	if m.Segments[0].NotScanned {
		t.Error("covered empty segment must record that it was scanned")
	}
	if !m.Segments[1].NotScanned {
		t.Error("uncovered empty segment must remain NotScanned")
	}
}

func TestBuild_SeverityRollup(t *testing.T) {
	rows := []ui.Row{
		row("192.168.1.10", ui.PortInfo{Port: 22, Severity: "info"}, ui.PortInfo{Port: 23, Severity: "high"}),
		row("192.168.1.11", ui.PortInfo{Port: 80, Severity: ""}),
		row("192.168.1.12"),
	}
	m := Build(rows, Input{Locals: homeLAN, Gateway: netinfo.Gateway{}})
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
	m := Build(rows, Input{Locals: homeLAN, Gateway: netinfo.Gateway{}})
	want := []string{"192.168.1.9", "192.168.1.10", "192.168.1.100"}
	for i, w := range want {
		if got := m.Segments[0].Nodes[i].Row.IP; got != w {
			t.Fatalf("node %d = %q, want %q (numeric order)", i, got, w)
		}
	}
}

func TestBuild_EmptyInputs(t *testing.T) {
	m := Build(nil, Input{Locals: nil, Gateway: netinfo.Gateway{}})
	if len(m.Segments) != 0 || len(m.Orphans) != 0 {
		t.Errorf("empty build should yield nothing, got %+v", m)
	}
	// Locals with no scan still produce segments, all marked unscanned.
	m = Build(nil, Input{Locals: homeLAN, Gateway: netinfo.Gateway{}})
	if len(m.Segments) != 1 || !m.Segments[0].NotScanned {
		t.Errorf("want 1 unscanned segment, got %+v", m.Segments)
	}
}
