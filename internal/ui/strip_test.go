package ui

import (
	"strings"
	"testing"

	"github.com/Emre-Diricanli/ndscan/internal/scan"
)

func TestStripControls(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"plain ascii", "OpenSSH 9.6", "OpenSSH 9.6"},
		{"ansi clear screen", "\x1b[2Jssh", "ssh"},
		{"ansi color wrap", "\x1b[1;31mEvil\x1b[0m", "Evil"},
		{"c1 csi", "\x9b2Jhost", "host"},
		{"two-byte escape", "\x1bcreset", "reset"},
		{"newline and tab dropped", "line1\nline2\tend", "line1line2end"},
		{"carriage return dropped", "fake\roverwrite", "fakeoverwrite"},
		{"del dropped", "a\x7fb", "ab"},
		{"legit utf-8 unchanged", "Acme — café 中文 ✔", "Acme — café 中文 ✔"},
		{"empty", "", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := stripControls(tc.in); got != tc.want {
				t.Errorf("stripControls(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

// XML 1.0 forbids literal control characters (even as char references), so
// the hostile input here uses tab — a valid-XML control character — to prove
// flatten strips controls at the boundary. Full ANSI-sequence coverage lives
// in TestStripControls.
const hostileXML = `<?xml version="1.0"?>
<nmaprun>
  <host>
    <status state="up"/>
    <address addr="192.168.86.66" addrtype="ipv4"/>
    <hostnames><hostname name="&#9;evil-host"/></hostnames>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open"/>
        <service name="ssh" product="Evil&#9;SSH" version="9&#9;.6" extrainfo="bo&#9;gus"/>
      </port>
    </ports>
  </host>
</nmaprun>`

func TestBuildRows_StripsHostileEscapes(t *testing.T) {
	res := []scan.HostResult{{IP: "192.168.86.66", XMLBytes: []byte(hostileXML)}}
	rows := BuildRows(res, nil, false, false, nil)
	if len(rows) != 1 {
		t.Fatalf("want 1 row, got %d", len(rows))
	}
	r := rows[0]
	if strings.ContainsAny(r.Host, "\x1b\t") || !strings.HasSuffix(r.Host, "evil-host") {
		t.Errorf("host = %q, want controls stripped", r.Host)
	}
	if len(r.PortDetails) != 1 {
		t.Fatalf("want 1 port, got %d", len(r.PortDetails))
	}
	p := r.PortDetails[0]
	if p.Product != "EvilSSH" {
		t.Errorf("product = %q, want %q", p.Product, "EvilSSH")
	}
	if p.Version != "9.6" {
		t.Errorf("version = %q, want %q", p.Version, "9.6")
	}
	if p.ExtraInfo != "bogus" {
		t.Errorf("extrainfo = %q, want %q", p.ExtraInfo, "bogus")
	}
	if len(r.Ports) != 1 || strings.ContainsAny(r.Ports[0], "\x1b\t") {
		t.Errorf("port label = %q, want controls stripped", r.Ports)
	}
}

func TestApplyHostnames_StripsPTREscapes(t *testing.T) {
	rows := []Row{{IP: "192.168.86.66"}}
	ApplyHostnames(rows, map[string]string{"192.168.86.66": "\x1b[2Jptr-host"})
	if rows[0].Host != "ptr-host" {
		t.Errorf("host = %q, want %q", rows[0].Host, "ptr-host")
	}
}
