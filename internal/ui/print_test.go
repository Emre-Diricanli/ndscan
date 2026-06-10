package ui

import (
	"testing"
	"time"

	"github.com/Emre-Diricanli/ndscan/internal/scan"
)

const hostXML = `<?xml version="1.0"?>
<nmaprun>
  <host>
    <status state="up"/>
    <address addr="192.168.86.51" addrtype="ipv4"/>
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
      <port protocol="tcp" portid="9">
        <state state="closed"/>
        <service name="discard"/>
      </port>
    </ports>
    <times srtt="2100"/>
  </host>
</nmaprun>`

func TestBuildRows_PortDetailsAndRTT(t *testing.T) {
	res := []scan.HostResult{{IP: "192.168.86.51", XMLBytes: []byte(hostXML)}}
	rows := BuildRows(res, nil, false, false, nil)
	if len(rows) != 1 {
		t.Fatalf("want 1 row, got %d", len(rows))
	}
	r := rows[0]

	if r.RTT != "2.1ms" {
		t.Errorf("RTT = %q, want 2.1ms", r.RTT)
	}
	// closed port must be excluded
	if len(r.PortDetails) != 2 {
		t.Fatalf("want 2 open ports, got %d (%+v)", len(r.PortDetails), r.PortDetails)
	}

	var ssh, smb *PortInfo
	for i := range r.PortDetails {
		switch r.PortDetails[i].Port {
		case 22:
			ssh = &r.PortDetails[i]
		case 445:
			smb = &r.PortDetails[i]
		}
	}
	if ssh == nil || smb == nil {
		t.Fatalf("missing expected ports: %+v", r.PortDetails)
	}
	if ssh.VersionLabel() != "OpenSSH 9.6" {
		t.Errorf("ssh version label = %q, want OpenSSH 9.6", ssh.VersionLabel())
	}
	if ssh.Severity != "info" {
		t.Errorf("ssh severity = %q, want info", ssh.Severity)
	}
	if smb.Severity != "warn" || smb.Risk == "" {
		t.Errorf("smb risk = %q/%q, want warn + reason", smb.Severity, smb.Risk)
	}
}

const fpXML = `<?xml version="1.0"?>
<nmaprun>
  <host>
    <status state="up"/>
    <address addr="192.168.86.45" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="8443">
        <state state="open"/>
        <service name="http" product="nginx" version="1.25" extrainfo="Ubuntu" tunnel="ssl">
          <cpe>cpe:/a:igor_sysoev:nginx:1.25</cpe>
        </service>
        <script id="http-title" output="Admin Console"/>
        <script id="ssl-cert" output="...">
          <table key="subject"><elem key="organizationName">Acme</elem></table>
          <table key="validity"><elem key="notAfter">2027-01-02T00:00:00</elem></table>
        </script>
      </port>
    </ports>
    <os><osmatch name="Linux 5.X" accuracy="92">
      <osclass type="general purpose" vendor="Linux" osfamily="Linux" accuracy="92">
        <cpe>cpe:/o:linux:linux_kernel:5</cpe>
      </osclass>
    </osmatch></os>
  </host>
</nmaprun>`

func TestBuildRows_Fingerprint(t *testing.T) {
	res := []scan.HostResult{{IP: "192.168.86.45", XMLBytes: []byte(fpXML)}}
	rows := BuildRows(res, nil, false, false, nil)
	if len(rows) != 1 {
		t.Fatalf("want 1 row, got %d", len(rows))
	}
	r := rows[0]
	if r.OS != "Linux 5.X" || r.OSAccuracy != 92 || r.OSCPE != "cpe:/o:linux:linux_kernel:5" {
		t.Errorf("OS detail = %q/%d/%q", r.OS, r.OSAccuracy, r.OSCPE)
	}
	if len(r.PortDetails) != 1 {
		t.Fatalf("want 1 port, got %d", len(r.PortDetails))
	}
	p := r.PortDetails[0]
	if !p.TLS {
		t.Error("port should be marked TLS")
	}
	if p.ExtraInfo != "Ubuntu" || p.CPE != "cpe:/a:igor_sysoev:nginx:1.25" {
		t.Errorf("port extra = %q / cpe %q", p.ExtraInfo, p.CPE)
	}
	if p.HTTPTitle != "Admin Console" {
		t.Errorf("http title = %q", p.HTTPTitle)
	}
	if p.Cert != "Acme — exp 2027-01-02" {
		t.Errorf("cert = %q", p.Cert)
	}
}

func TestFormatRTT(t *testing.T) {
	cases := []struct {
		d    time.Duration
		want string
	}{
		{400 * time.Microsecond, "0.4ms"},
		{2100 * time.Microsecond, "2.1ms"},
		{45 * time.Millisecond, "45ms"},
		{1500 * time.Millisecond, "1.50s"},
	}
	for _, c := range cases {
		if got := formatRTT(c.d); got != c.want {
			t.Errorf("formatRTT(%v) = %q, want %q", c.d, got, c.want)
		}
	}
}
