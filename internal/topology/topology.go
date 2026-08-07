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
	"net/netip"
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
	addr      netip.Addr
}

// Segment is one network, with the hosts found on it.
type Segment struct {
	CIDR      string // e.g. "192.168.2.0/24"
	Interface string // e.g. "en0" ("" when inferred from results alone)
	SelfAddr  string // this machine's address on it, if any
	Nodes     []Node
	// NotScanned means no scan covered this network — not that a scan looked
	// and found nothing. Those are opposite facts and must not render alike:
	// "I checked, it's empty" is a finding; "I never checked" is a gap.
	NotScanned bool
	// RoutedVia is set on segments this machine is NOT attached to but reached
	// through the gateway (a sibling VLAN, a remote SSH scan). It holds the
	// gateway IP the traffic transited, so the map can show the segment nested
	// under the gateway rather than as a peer of an attached network.
	RoutedVia string
}

// Attached reports whether this machine has an interface on the segment.
// Routed and orphan segments are not attached.
func (s Segment) Attached() bool { return s.Interface != "" }

// parseCoverage turns scan targets into prefixes. A bare address counts as
// covering only itself, which is what a single-host scan actually did.
func parseCoverage(targets []string) []netip.Prefix {
	out := make([]netip.Prefix, 0, len(targets))
	for _, t := range targets {
		if p, err := netip.ParsePrefix(t); err == nil {
			out = append(out, p.Masked())
			continue
		}
		if a, err := netip.ParseAddr(t); err == nil {
			out = append(out, netip.PrefixFrom(a, a.BitLen()))
		}
	}
	return out
}

// coversNetwork reports whether the scan reached into the given network.
//
// Any overlap counts. Scanning half a subnet still means we looked there, and
// reporting it as untouched would hide the hosts we did find; the honest
// distinction is "looked" versus "never looked", not "looked exhaustively".
func coversNetwork(covered []netip.Prefix, net netip.Prefix) bool {
	for _, c := range covered {
		if c.Overlaps(net) {
			return true
		}
	}
	return false
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
	worst := ""
	for _, p := range r.PortDetails {
		if severityRank(p.Severity) > severityRank(worst) {
			worst = p.Severity
		}
	}
	return worst
}

func severityRank(s string) int {
	switch s {
	case "high":
		return 3
	case "warn":
		return 2
	case "info":
		return 1
	default:
		return 0
	}
}

// Input is everything Build needs about the machine and the scan that produced
// the rows. Passing it in (rather than calling netinfo here) keeps Build pure
// and testable.
type Input struct {
	// Locals are the networks this machine is attached to.
	Locals []netinfo.Network
	// Gateway is the default next hop.
	Gateway netinfo.Gateway
	// Coverage lists what the scan actually targeted. Without it, a segment
	// with no hosts is ambiguous: coverage is the only thing that separates
	// "scanned, nothing there" from "never looked". Callers that genuinely
	// don't know may leave it nil, and every empty segment then reports as
	// unscanned — the old, pessimistic behaviour.
	Coverage []string
}

// Build assembles the map from scan rows plus the machine's own networks.
func Build(rows []ui.Row, in Input) Map {
	type seg struct {
		net   netip.Prefix
		index int
	}

	m := Map{Gateway: in.Gateway.IP}
	var parsed []seg
	covered := parseCoverage(in.Coverage)

	// Seed one segment per attached network, in interface order.
	for _, l := range in.Locals {
		ipnet, err := netip.ParsePrefix(l.CIDR)
		if err != nil {
			continue
		}
		m.Segments = append(m.Segments, Segment{
			CIDR:      l.CIDR,
			Interface: l.Interface,
			SelfAddr:  l.Addr,
			// A segment the scan covered is "scanned" whether or not anything
			// answered. Only segments outside the scan's reach stay unscanned.
			NotScanned: !coversNetwork(covered, ipnet),
		})
		parsed = append(parsed, seg{net: ipnet, index: len(m.Segments) - 1})
	}

	// Place each scanned host into the first network that contains it.
	for _, r := range rows {
		ip, ipOK := netip.ParseAddr(r.IP)
		node := Node{
			Row:       r,
			Severity:  worstSeverity(r),
			IsGateway: in.Gateway.IP != "" && r.IP == in.Gateway.IP,
			addr:      ip,
		}
		placed := false
		if ipOK == nil {
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
	// renders as a network rather than a flat list. Hosts outside every
	// attached network were reached through the gateway, so tag the resulting
	// segments as routed-via that gateway (when we know it) — this is what
	// lets the map draw them nested under the gateway rather than as peers of
	// the local LAN.
	if len(m.Orphans) > 0 {
		routed := orphanSegments(m.Orphans)
		for i := range routed {
			routed[i].RoutedVia = in.Gateway.IP
		}
		m.Segments = append(m.Segments, routed...)
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
		ip, err := netip.ParseAddr(n.Row.IP)
		key := "unknown"
		if err == nil && ip.Is4() {
			key = netip.PrefixFrom(ip, 24).Masked().String()
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
		if nodes[i].addr.IsValid() && nodes[j].addr.IsValid() {
			return nodes[i].addr.Compare(nodes[j].addr) < 0
		}
		return ui.IPLess(nodes[i].Row.IP, nodes[j].Row.IP)
	})
}
