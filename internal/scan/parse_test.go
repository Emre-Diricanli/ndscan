package scan

import (
	"testing"
	"time"
)

const sampleXML = `<?xml version="1.0"?>
<nmaprun>
  <host>
    <status state="up"/>
    <address addr="192.168.86.51" addrtype="ipv4"/>
    <address addr="f0:09:0d:cd:a7:01" addrtype="mac" vendor="Apple"/>
    <hostnames><hostname name="my-mac"/></hostnames>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open"/>
        <service name="ssh" product="OpenSSH" version="9.6"/>
      </port>
      <port protocol="tcp" portid="445">
        <state state="open"/>
        <service name="microsoft-ds"/>
      </port>
    </ports>
    <os><osmatch name="macOS 14" accuracy="96"/></os>
    <times srtt="2100"/>
  </host>
</nmaprun>`

func TestParseOne_RTTAndService(t *testing.T) {
	nr, err := ParseOne([]byte(sampleXML))
	if err != nil {
		t.Fatalf("ParseOne: %v", err)
	}
	if len(nr.Hosts) != 1 {
		t.Fatalf("want 1 host, got %d", len(nr.Hosts))
	}
	h := nr.Hosts[0]

	if got := h.RTT(); got != 2100*time.Microsecond {
		t.Errorf("RTT = %v, want 2.1ms", got)
	}
	if got := h.BestOSGuess(); got != "macOS 14" {
		t.Errorf("BestOSGuess = %q, want macOS 14", got)
	}
	if len(h.Ports.List) != 2 {
		t.Fatalf("want 2 ports, got %d", len(h.Ports.List))
	}
	if h.Ports.List[0].Service.Product != "OpenSSH" || h.Ports.List[0].Service.Version != "9.6" {
		t.Errorf("ssh service = %+v, want OpenSSH 9.6", h.Ports.List[0].Service)
	}
}

func TestRTT_ZeroWhenAbsent(t *testing.T) {
	var h Host
	if got := h.RTT(); got != 0 {
		t.Errorf("RTT with no times = %v, want 0", got)
	}
}

// fingerprintXML mirrors real nmap -sV --script ssl-cert,http-title output:
// a TLS service with a CPE, extrainfo, an ssl-cert table, and an http-title.
const fingerprintXML = `<?xml version="1.0"?>
<nmaprun>
  <host>
    <status state="up"/>
    <address addr="192.168.86.45" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="8443">
        <state state="open"/>
        <service name="http" product="BaseHTTPServer" version="0.6" extrainfo="Python 3.14.3" tunnel="ssl">
          <cpe>cpe:/a:python:python:3.14.3</cpe>
        </service>
        <script id="http-title" output="Acme Router Admin"/>
        <script id="ssl-cert" output="Subject: commonName=ndscan-test...">
          <table key="subject">
            <elem key="commonName">ndscan-test</elem>
            <elem key="organizationName">Acme Inc</elem>
          </table>
          <table key="issuer">
            <elem key="commonName">ndscan-test</elem>
          </table>
          <table key="validity">
            <elem key="notBefore">2026-06-10T14:59:44</elem>
            <elem key="notAfter">2027-06-10T14:59:44</elem>
          </table>
        </script>
      </port>
    </ports>
    <os>
      <osmatch name="HP embedded" accuracy="94">
        <osclass type="printer" vendor="HP" osfamily="embedded" accuracy="94">
          <cpe>cpe:/h:hp:laserjet</cpe>
        </osclass>
      </osmatch>
    </os>
  </host>
</nmaprun>`

func TestParse_ServiceFingerprint(t *testing.T) {
	nr, err := ParseOne([]byte(fingerprintXML))
	if err != nil {
		t.Fatalf("ParseOne: %v", err)
	}
	h := nr.Hosts[0]
	p := h.Ports.List[0]

	if got := p.Service.CPE(); got != "cpe:/a:python:python:3.14.3" {
		t.Errorf("service CPE = %q", got)
	}
	if p.Service.ExtraInfo != "Python 3.14.3" {
		t.Errorf("extrainfo = %q", p.Service.ExtraInfo)
	}
	if p.Service.Tunnel != "ssl" {
		t.Errorf("tunnel = %q, want ssl", p.Service.Tunnel)
	}
	if got := p.HTTPTitle(); got != "Acme Router Admin" {
		t.Errorf("http title = %q", got)
	}
	cert := p.TLSCert()
	if cert == nil {
		t.Fatal("expected a TLS cert")
	}
	if cert.Organization != "Acme Inc" || cert.NotAfter != "2027-06-10T14:59:44" {
		t.Errorf("cert = %+v", cert)
	}
	if got := cert.Summary(); got != "Acme Inc — exp 2027-06-10" {
		t.Errorf("cert summary = %q", got)
	}
}

func TestParse_OSDetail(t *testing.T) {
	nr, _ := ParseOne([]byte(fingerprintXML))
	d := nr.Hosts[0].BestOSDetail()
	if d == nil {
		t.Fatal("expected OS detail")
	}
	if d.Name != "HP embedded" || d.Accuracy != 94 {
		t.Errorf("os name/acc = %q/%d", d.Name, d.Accuracy)
	}
	if d.Vendor != "HP" || d.Family != "embedded" {
		t.Errorf("os class = %q/%q", d.Vendor, d.Family)
	}
	if d.CPE != "cpe:/h:hp:laserjet" {
		t.Errorf("os cpe = %q", d.CPE)
	}
}

func TestTLSCert_NilWhenAbsent(t *testing.T) {
	nr, _ := ParseOne([]byte(sampleXML)) // sampleXML has no scripts
	if c := nr.Hosts[0].Ports.List[0].TLSCert(); c != nil {
		t.Errorf("expected nil cert, got %+v", c)
	}
}
