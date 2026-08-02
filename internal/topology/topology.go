// Package topology arranges scan results into the network map shown in the
// TUI: the networks this machine is attached to, the default gateway, and the
// hosts found on each network.
//
// It is deliberately honest about what it knows. A network this machine is on
// but did not scan is marked NotScanned rather than drawn as empty, and hosts
// that fall outside every known network are grouped separately instead of being
// silently attached to the wrong one.
package topology

import (
	"net"
	"sort"

	"github.com/Emre-Diricanli/ndscan/internal/netinfo"
	"github.com/Emre-Diricanli/ndscan/internal/ui"
)

// Node is one host placed on the map.
type Node struct {
	Row       ui.Row
	IsGateway bool // the default next hop
	IsSelf    bool // this machine
	Severity  string
}

// Segment is one network, with the hosts found on it.
type Segment struct {
	CIDR       string // e.g. "192.168.2.0/24"
	Interface  string // e.g. "en0" ("" when inferred from results alone)
	SelfAddr   string // this machine's address on it, if any
	Nodes      []Node
	NotScanned bool // attached to this network, but no scan covered it
}

// Map is the full topology.
type Map struct {
	Segments []Segment
	Gateway  string // default gateway IP, "" if unknown
	// Orphans are scanned hosts that don't fall inside any known network
	// (e.g. a remote SSH scan of a subnet this machine isn't on).
	Orphans []Node
}

// HostCount returns the number of hosts placed on the segment.
func (s Segment) HostCount() int { return len(s.Nodes) }

// worstSeverity returns the highest-ranked severity among a row's open ports.
func worstSeverity(r ui.Row) string {
	rank := map[string]int{"": 0, "info": 1, "warn": 2, "high": 3}
	worst := ""
	for _, p := range r.PortDetails {
		if rank[p.Severity] > rank[worst] {
			worst = p.Severity
		}
	}
	return worst
}

// Build assembles the map from scan rows plus the machine's own networks.
//
// locals and gateway come from netinfo; passing them in (rather than calling
// netinfo here) keeps Build pure and testable.
func Build(rows []ui.Row, locals []netinfo.Network, gateway netinfo.Gateway) Map {
	type seg struct {
		net   *net.IPNet
		index int
	}

	m := Map{Gateway: gateway.IP}
	var parsed []seg

	// Seed one segment per attached network, in interface order.
	for _, l := range locals {
		_, ipnet, err := net.ParseCIDR(l.CIDR)
		if err != nil {
			continue
		}
		m.Segments = append(m.Segments, Segment{
			CIDR:      l.CIDR,
			Interface: l.Interface,
			SelfAddr:  l.Addr,
			// Assume nothing was scanned until a row lands here.
			NotScanned: true,
		})
		parsed = append(parsed, seg{net: ipnet, index: len(m.Segments) - 1})
	}

	// Place each scanned host into the first network that contains it.
	for _, r := range rows {
		ip := net.ParseIP(r.IP)
		node := Node{
			Row:       r,
			Severity:  worstSeverity(r),
			IsGateway: gateway.IP != "" && r.IP == gateway.IP,
		}
		placed := false
		if ip != nil {
			for _, p := range parsed {
				if !p.net.Contains(ip) {
					continue
				}
				s := &m.Segments[p.index]
				node.IsSelf = s.SelfAddr != "" && r.IP == s.SelfAddr
				s.Nodes = append(s.Nodes, node)
				s.NotScanned = false
				placed = true
				break
			}
		}
		if !placed {
			m.Orphans = append(m.Orphans, node)
		}
	}

	// Group orphans into synthetic segments by /24 so a remote scan still
	// renders as a network rather than a flat list.
	if len(m.Orphans) > 0 {
		m.Segments = append(m.Segments, orphanSegments(m.Orphans)...)
		m.Orphans = nil
	}

	for i := range m.Segments {
		sortNodes(m.Segments[i].Nodes)
	}
	return m
}

// orphanSegments buckets hosts with no matching local network into /24 groups.
func orphanSegments(orphans []Node) []Segment {
	byNet := map[string][]Node{}
	var order []string
	for _, n := range orphans {
		ip := net.ParseIP(n.Row.IP)
		key := "unknown"
		if v4 := ip.To4(); v4 != nil {
			key = v4.Mask(net.CIDRMask(24, 32)).String() + "/24"
		}
		if _, seen := byNet[key]; !seen {
			order = append(order, key)
		}
		byNet[key] = append(byNet[key], n)
	}
	sort.Strings(order)
	out := make([]Segment, 0, len(order))
	for _, key := range order {
		out = append(out, Segment{CIDR: key, Nodes: byNet[key]})
	}
	return out
}

// sortNodes orders hosts within a segment: gateway first (it anchors the
// drawing), then numerically by address.
func sortNodes(nodes []Node) {
	sort.SliceStable(nodes, func(i, j int) bool {
		if nodes[i].IsGateway != nodes[j].IsGateway {
			return nodes[i].IsGateway
		}
		return ui.IPLess(nodes[i].Row.IP, nodes[j].Row.IP)
	})
}
