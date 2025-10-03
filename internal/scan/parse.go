package scan

import (
	"encoding/xml"
)

type NmapRun struct {
	Hosts []Host `xml:"host"`
}

type Host struct {
	Status    Status    `xml:"status"`
	Addresses []Address `xml:"address"`
	Hostnames Hostnames `xml:"hostnames"`
	Ports     Ports     `xml:"ports"`
}

type Status struct {
	State string `xml:"state,attr"`
}

type Address struct {
	Addr     string `xml:"addr,attr"`
	AddrType string `xml:"addrtype,attr"`
	Vendor   string `xml:"vendor,attr,omitempty"`
}

type Hostnames struct {
	Names []Hostname `xml:"hostname"`
}
type Hostname struct {
	Name string `xml:"name,attr"`
}

type Ports struct {
	List []Port `xml:"port"`
}
type Port struct {
	Protocol string    `xml:"protocol,attr"`
	PortID   int       `xml:"portid,attr"`
	State    PortState `xml:"state"`
	Service  Service   `xml:"service"`
}
type PortState struct {
	State string `xml:"state,attr"`
}
type Service struct {
	Name    string `xml:"name,attr,omitempty"`
	Product string `xml:"product,attr,omitempty"`
	Version string `xml:"version,attr,omitempty"`
}

func ParseOne(xmlBytes []byte) (NmapRun, error) {
	var nr NmapRun
	err := xml.Unmarshal(xmlBytes, &nr)
	return nr, err
}
