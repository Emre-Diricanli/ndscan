package web

import (
	"github.com/Emre-Diricanli/ndscan/internal/topology"
	"github.com/Emre-Diricanli/ndscan/internal/ui"
)

// The types here are the wire format defined in docs/web-api-contract.md.
// They are deliberately separate from the internal model types: the browser
// contract must stay stable even when internal structs are refactored, and the
// internal types carry unexported fields that cannot be serialized anyway.

type portDTO struct {
	Port     int    `json:"port"`
	Proto    string `json:"proto"`
	Service  string `json:"service,omitempty"`
	Product  string `json:"product,omitempty"`
	Version  string `json:"version,omitempty"`
	TLS      bool   `json:"tls,omitempty"`
	Severity string `json:"severity,omitempty"`
	Risk     string `json:"risk,omitempty"`
}

type hostDTO struct {
	IP       string    `json:"ip"`
	Hostname string    `json:"hostname,omitempty"`
	MAC      string    `json:"mac,omitempty"`
	Vendor   string    `json:"vendor,omitempty"`
	OS       string    `json:"os,omitempty"`
	RTT      string    `json:"rtt,omitempty"`
	Up       bool      `json:"up"`
	Ports    []portDTO `json:"ports,omitempty"`
}

type nodeDTO struct {
	IsGateway bool    `json:"isGateway"`
	IsSelf    bool    `json:"isSelf"`
	Severity  string  `json:"severity,omitempty"`
	Host      hostDTO `json:"host"`
}

type segmentDTO struct {
	CIDR       string    `json:"cidr"`
	Interface  string    `json:"interface,omitempty"`
	SelfAddr   string    `json:"selfAddr,omitempty"`
	NotScanned bool      `json:"notScanned"`
	RoutedVia  string    `json:"routedVia,omitempty"`
	Nodes      []nodeDTO `json:"nodes"`
}

type topologyDTO struct {
	Gateway  string       `json:"gateway,omitempty"`
	Segments []segmentDTO `json:"segments"`
}

func toHostDTO(r ui.Row) hostDTO {
	h := hostDTO{
		IP: r.IP, Hostname: r.Host, MAC: r.MAC, Vendor: r.Vendor,
		OS: r.OS, RTT: r.RTT, Up: r.Up,
	}
	for _, p := range r.PortDetails {
		h.Ports = append(h.Ports, portDTO{
			Port: p.Port, Proto: p.Proto, Service: p.Service,
			Product: p.Product, Version: p.Version, TLS: p.TLS,
			Severity: p.Severity, Risk: p.Risk,
		})
	}
	return h
}

// toTopologyDTO converts the internal map to the wire format. Nodes is always
// a non-nil slice so the frontend can iterate without a null check.
func toTopologyDTO(m topology.Map) topologyDTO {
	out := topologyDTO{Gateway: m.Gateway, Segments: make([]segmentDTO, 0, len(m.Segments))}
	for _, s := range m.Segments {
		seg := segmentDTO{
			CIDR: s.CIDR, Interface: s.Interface, SelfAddr: s.SelfAddr,
			NotScanned: s.NotScanned, RoutedVia: s.RoutedVia,
			Nodes: make([]nodeDTO, 0, len(s.Nodes)),
		}
		for _, n := range s.Nodes {
			seg.Nodes = append(seg.Nodes, nodeDTO{
				IsGateway: n.IsGateway, IsSelf: n.IsSelf,
				Severity: n.Severity, Host: toHostDTO(n.Row),
			})
		}
		out.Segments = append(out.Segments, seg)
	}
	return out
}
