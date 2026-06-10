package scan

import (
	"encoding/xml"
	"time"
)

type NmapRun struct {
	Hosts []Host `xml:"host"`
}

type Host struct {
	Status    Status    `xml:"status"`
	Addresses []Address `xml:"address"`
	Hostnames Hostnames `xml:"hostnames"`
	Ports     Ports     `xml:"ports"`
	OS        OS        `xml:"os"`
	Times     Times     `xml:"times"`
}

// Times holds nmap's timing data; srtt is the smoothed round-trip time in
// microseconds (populated once nmap has probed the host).
type Times struct {
	SRTT int `xml:"srtt,attr"`
}

// RTT returns the host's smoothed round-trip time, or 0 if nmap reported none.
func (h Host) RTT() time.Duration {
	if h.Times.SRTT <= 0 {
		return 0
	}
	return time.Duration(h.Times.SRTT) * time.Microsecond
}

// OS holds nmap's OS-detection guesses (populated by -A / -O presets).
type OS struct {
	Matches []OSMatch `xml:"osmatch"`
}

type OSMatch struct {
	Name     string `xml:"name,attr"`
	Accuracy int    `xml:"accuracy,attr"`
}

// BestOSGuess returns the highest-accuracy OS match name, or "".
func (h Host) BestOSGuess() string {
	best := ""
	acc := -1
	for _, m := range h.OS.Matches {
		if m.Accuracy > acc {
			best, acc = m.Name, m.Accuracy
		}
	}
	return best
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
