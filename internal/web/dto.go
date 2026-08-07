package web

import (
	"github.com/Emre-Diricanli/ndscan/internal/topology"
	"github.com/Emre-Diricanli/ndscan/internal/ui"
	"github.com/Emre-Diricanli/ndscan/internal/vendor"
)

// The types here are the wire format defined in docs/web-api-contract.md.
// They are deliberately separate from the internal model types: the browser
// contract must stay stable even when internal structs are refactored, and the
// internal types carry unexported fields that cannot be serialized anyway.

type portDTO struct {
	Port      int    `json:"port"`
	Proto     string `json:"proto"`
	Service   string `json:"service,omitempty"`
	Product   string `json:"product,omitempty"`
	Version   string `json:"version,omitempty"`
	ExtraInfo string `json:"extraInfo,omitempty"`
	CPE       string `json:"cpe,omitempty"`
	TLS       bool   `json:"tls,omitempty"`
	HTTPTitle string `json:"httpTitle,omitempty"`
	Cert      string `json:"cert,omitempty"`
	Severity  string `json:"severity,omitempty"`
	Risk      string `json:"risk,omitempty"`
}

type hostDTO struct {
	IP       string `json:"ip"`
	Hostname string `json:"hostname,omitempty"`
	MAC      string `json:"mac,omitempty"`
	Vendor   string `json:"vendor,omitempty"`
	// MACKind explains an empty Vendor: "randomized" means the host uses a
	// privacy MAC and no vendor exists to look up, which is different from a
	// lookup that simply failed.
	MACKind    string    `json:"macKind,omitempty"`
	OS         string    `json:"os,omitempty"`
	OSAccuracy int       `json:"osAccuracy,omitempty"` // 0-100 confidence
	OSCPE      string    `json:"osCpe,omitempty"`
	RTT        string    `json:"rtt,omitempty"`
	Up         bool      `json:"up"`
	Ports      []portDTO `json:"ports,omitempty"`
}

type nodeDTO struct {
	IsGateway bool    `json:"isGateway"`
	IsSelf    bool    `json:"isSelf"`
	Severity  string  `json:"severity,omitempty"`
	Host      hostDTO `json:"host"`
}

type segmentDTO struct {
	CIDR      string `json:"cidr"`
	Interface string `json:"interface,omitempty"`
	SelfAddr  string `json:"selfAddr,omitempty"`
	// Inferred marks a network boundary that was guessed rather than observed
	// on an interface or supplied as a scan target. It must reach the browser
	// so a guessed boundary can never render as a measured fact.
	Inferred   bool      `json:"inferred"`
	NotScanned bool      `json:"notScanned"`
	RoutedVia  string    `json:"routedVia,omitempty"`
	Nodes      []nodeDTO `json:"nodes"`
}

type topologyDTO struct {
	Gateway  string       `json:"gateway,omitempty"`
	Segments []segmentDTO `json:"segments"`
	// Orphans are hosts that answered the scan but fall inside no attached
	// network and no scan target. They stay out of Segments precisely because
	// no CIDR honestly contains them — but dropping them entirely would make a
	// live host vanish from the map, so they travel under their own key.
	Orphans []nodeDTO `json:"orphans,omitempty"`
}

func toHostDTO(r ui.Row) hostDTO {
	h := hostDTO{
		IP: r.IP, Hostname: r.Host, MAC: r.MAC, Vendor: r.Vendor,
		OS: r.OS, OSAccuracy: r.OSAccuracy, OSCPE: r.OSCPE,
		RTT: r.RTT, Up: r.Up,
	}
	if r.MAC != "" {
		h.MACKind = string(vendor.Classify(r.MAC))
		if h.Vendor == "" {
			h.Vendor = vendor.Describe(nil, r.MAC)
		}
	}
	for _, p := range r.PortDetails {
		h.Ports = append(h.Ports, portDTO{
			Port: p.Port, Proto: p.Proto, Service: p.Service,
			Product: p.Product, Version: p.Version, ExtraInfo: p.ExtraInfo,
			CPE: p.CPE, TLS: p.TLS, HTTPTitle: p.HTTPTitle, Cert: p.Cert,
			Severity: p.Severity, Risk: p.Risk,
		})
	}
	return h
}

// toTopologyDTO converts the internal map to the wire format. Nodes is always
// a non-nil slice so the frontend can iterate without a null check; Orphans is
// the opposite — omitted when empty, so a map without orphans emits no section
// for them at all.
func toTopologyDTO(m topology.Map) topologyDTO {
	out := topologyDTO{Gateway: m.Gateway, Segments: make([]segmentDTO, 0, len(m.Segments))}
	for _, s := range m.Segments {
		seg := segmentDTO{
			CIDR: s.CIDR, Interface: s.Interface, SelfAddr: s.SelfAddr,
			Inferred: s.Inferred, NotScanned: s.NotScanned, RoutedVia: s.RoutedVia,
			Nodes: make([]nodeDTO, 0, len(s.Nodes)),
		}
		for _, n := range s.Nodes {
			seg.Nodes = append(seg.Nodes, toNodeDTO(n))
		}
		out.Segments = append(out.Segments, seg)
	}
	for _, n := range m.Orphans {
		out.Orphans = append(out.Orphans, toNodeDTO(n))
	}
	return out
}

func toNodeDTO(n topology.Node) nodeDTO {
	return nodeDTO{
		IsGateway: n.IsGateway, IsSelf: n.IsSelf,
		Severity: n.Severity, Host: toHostDTO(n.Row),
	}
}
