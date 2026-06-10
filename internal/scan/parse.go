package scan

import (
	"encoding/xml"
	"strings"
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
	Name     string    `xml:"name,attr"`
	Accuracy int       `xml:"accuracy,attr"`
	Classes  []OSClass `xml:"osclass"`
}

// OSClass is nmap's structured OS classification (vendor/family/generation)
// with optional CPE identifiers.
type OSClass struct {
	Type     string   `xml:"type,attr"`
	Vendor   string   `xml:"vendor,attr"`
	OSFamily string   `xml:"osfamily,attr"`
	OSGen    string   `xml:"osgen,attr"`
	Accuracy int      `xml:"accuracy,attr"`
	CPEs     []string `xml:"cpe"`
}

// BestOSGuess returns the highest-accuracy OS match name, or "".
func (h Host) BestOSGuess() string {
	if m := h.bestMatch(); m != nil {
		return m.Name
	}
	return ""
}

// bestMatch returns the highest-accuracy OS match, or nil.
func (h Host) bestMatch() *OSMatch {
	var best *OSMatch
	acc := -1
	for i := range h.OS.Matches {
		if h.OS.Matches[i].Accuracy > acc {
			best, acc = &h.OS.Matches[i], h.OS.Matches[i].Accuracy
		}
	}
	return best
}

// OSDetail describes the best OS guess in structured form for the detail pane.
type OSDetail struct {
	Name     string // full match name, e.g. "Linux 5.4 - 5.10"
	Accuracy int    // 0-100 confidence
	Vendor   string // e.g. "Linux", "HP", "Apple"
	Family   string // e.g. "Linux", "embedded", "macOS"
	Gen      string // e.g. "5.X"
	CPE      string // first OS CPE, e.g. "cpe:/o:linux:linux_kernel:5"
}

// BestOSDetail returns the structured best OS guess, or nil if none.
func (h Host) BestOSDetail() *OSDetail {
	m := h.bestMatch()
	if m == nil {
		return nil
	}
	d := &OSDetail{Name: m.Name, Accuracy: m.Accuracy}
	if len(m.Classes) > 0 {
		c := m.Classes[0]
		d.Vendor, d.Family, d.Gen = c.Vendor, c.OSFamily, c.OSGen
		if len(c.CPEs) > 0 {
			d.CPE = c.CPEs[0]
		}
	}
	return d
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
	Scripts  []Script  `xml:"script"`
}
type PortState struct {
	State string `xml:"state,attr"`
}
type Service struct {
	Name      string   `xml:"name,attr,omitempty"`
	Product   string   `xml:"product,attr,omitempty"`
	Version   string   `xml:"version,attr,omitempty"`
	ExtraInfo string   `xml:"extrainfo,attr,omitempty"`
	Tunnel    string   `xml:"tunnel,attr,omitempty"` // e.g. "ssl"
	CPEs      []string `xml:"cpe"`
}

// Script is one NSE script result attached to a port (from --script / -A).
type Script struct {
	ID     string        `xml:"id,attr"`
	Output string        `xml:"output,attr"`
	Tables []ScriptTable `xml:"table"`
	Elems  []ScriptElem  `xml:"elem"`
}

// ScriptTable is a (possibly nested) keyed table within a script result.
type ScriptTable struct {
	Key    string        `xml:"key,attr"`
	Tables []ScriptTable `xml:"table"`
	Elems  []ScriptElem  `xml:"elem"`
}

// ScriptElem is a single key/value leaf in a script result.
type ScriptElem struct {
	Key   string `xml:"key,attr"`
	Value string `xml:",chardata"`
}

// CPE returns the service's first CPE identifier, or "".
func (s Service) CPE() string {
	if len(s.CPEs) > 0 {
		return s.CPEs[0]
	}
	return ""
}

// script returns the first script on the port matching id, or nil.
func (p Port) script(id string) *Script {
	for i := range p.Scripts {
		if p.Scripts[i].ID == id {
			return &p.Scripts[i]
		}
	}
	return nil
}

// HTTPTitle returns the page title reported by the http-title script, or "".
func (p Port) HTTPTitle() string {
	s := p.script("http-title")
	if s == nil {
		return ""
	}
	// http-title puts the title in the output, sometimes suffixed with
	// "(redirect ...)" or "Requested resource was ..."; keep the first line.
	title := firstLine(s.Output)
	if strings.HasPrefix(title, "Site doesn't have a title") {
		return ""
	}
	return title
}

// TLSCert is a condensed view of an ssl-cert script result.
type TLSCert struct {
	CommonName   string // subject CN
	Organization string // subject O
	Issuer       string // issuer CN
	NotAfter     string // expiry, e.g. "2027-06-10T14:59:44"
}

// Summary renders the cert compactly, e.g. "Acme Inc — exp 2027-06-10".
func (c TLSCert) Summary() string {
	name := c.CommonName
	if c.Organization != "" {
		name = c.Organization
	}
	exp := c.NotAfter
	if i := strings.IndexByte(exp, 'T'); i > 0 {
		exp = exp[:i] // keep the date, drop the time
	}
	switch {
	case name != "" && exp != "":
		return name + " — exp " + exp
	case name != "":
		return name
	default:
		return exp
	}
}

// TLSCert extracts the certificate summary from the ssl-cert script, or nil.
func (p Port) TLSCert() *TLSCert {
	s := p.script("ssl-cert")
	if s == nil {
		return nil
	}
	c := &TLSCert{}
	for _, tbl := range s.Tables {
		switch tbl.Key {
		case "subject":
			c.CommonName = elemValue(tbl.Elems, "commonName")
			c.Organization = elemValue(tbl.Elems, "organizationName")
		case "issuer":
			c.Issuer = elemValue(tbl.Elems, "commonName")
		case "validity":
			c.NotAfter = elemValue(tbl.Elems, "notAfter")
		}
	}
	if c.CommonName == "" && c.Organization == "" && c.NotAfter == "" {
		return nil
	}
	return c
}

func elemValue(elems []ScriptElem, key string) string {
	for _, e := range elems {
		if e.Key == key {
			return strings.TrimSpace(e.Value)
		}
	}
	return ""
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return strings.TrimSpace(s[:i])
	}
	return strings.TrimSpace(s)
}

func ParseOne(xmlBytes []byte) (NmapRun, error) {
	var nr NmapRun
	err := xml.Unmarshal(xmlBytes, &nr)
	return nr, err
}
