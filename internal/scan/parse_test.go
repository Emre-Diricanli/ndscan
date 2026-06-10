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
