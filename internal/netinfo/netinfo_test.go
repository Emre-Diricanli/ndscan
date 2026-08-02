package netinfo

import (
	"net"
	"testing"
)

// macOS `netstat -rn -f inet` output. Note the abbreviated destinations
// ("10.11/16", "127") that BSD emits and that must be expanded to real CIDRs.
const darwinRoutes = `Routing tables

Internet:
Destination        Gateway            Flags               Netif Expire
default            192.168.1.1        UGScg                 en0
default            link#24            UCSIg               utun8
10.11/16           link#24            UCS                 utun8
100.64/10          link#24            UCS                 utun8
100.100.100.100/32 link#24            UCS                 utun8
127                127.0.0.1          UCS                   lo0
127.0.0.1          127.0.0.1          UH                    lo0
192.168.1.0/24     link#4             UCS                   en0
`

// Linux `netstat -rn` / `route -n` style output.
const linuxRoutes = `Kernel IP routing table
Destination     Gateway         Genmask         Flags   MSS Window  irtt Iface
0.0.0.0         10.0.0.1        0.0.0.0         UG        0 0          0 eth0
10.0.0.0        0.0.0.0         255.255.255.0   U         0 0          0 eth0
172.17.0.0      0.0.0.0         255.255.0.0     U         0 0          0 docker0
`

func TestParseDefaultGateway_Darwin(t *testing.T) {
	gw, iface := parseDefaultGateway(darwinRoutes)
	if gw != "192.168.1.1" {
		t.Errorf("gateway = %q, want 192.168.1.1", gw)
	}
	if iface != "en0" {
		t.Errorf("iface = %q, want en0", iface)
	}
}

func TestParseDefaultGateway_Linux(t *testing.T) {
	gw, iface := parseDefaultGateway(linuxRoutes)
	if gw != "10.0.0.1" {
		t.Errorf("gateway = %q, want 10.0.0.1", gw)
	}
	if iface != "eth0" {
		t.Errorf("iface = %q, want eth0", iface)
	}
}

// A "default" row whose gateway is a link (link#24, as VPN tunnels emit) is not
// a usable next-hop address and must be skipped in favor of a real IP.
func TestParseDefaultGateway_SkipsLinkGateways(t *testing.T) {
	const linkFirst = `Destination        Gateway            Flags   Netif
default            link#24            UCSIg   utun8
default            192.168.1.1        UGScg   en0
`
	gw, iface := parseDefaultGateway(linkFirst)
	if gw != "192.168.1.1" || iface != "en0" {
		t.Errorf("got %q/%q, want 192.168.1.1/en0", gw, iface)
	}
}

func TestParseDefaultGateway_NoneFound(t *testing.T) {
	if gw, _ := parseDefaultGateway("Destination Gateway\n10.0.0.0/8 link#1\n"); gw != "" {
		t.Errorf("gateway = %q, want empty", gw)
	}
	if gw, _ := parseDefaultGateway(""); gw != "" {
		t.Errorf("gateway = %q, want empty", gw)
	}
}

// BSD abbreviates network destinations; expand them back to canonical CIDRs.
func TestExpandBSDNetwork(t *testing.T) {
	cases := []struct{ in, want string }{
		{"10.11/16", "10.11.0.0/16"},
		{"100.64/10", "100.64.0.0/10"},
		{"127", "127.0.0.0/8"},
		{"192.168.1.0/24", "192.168.1.0/24"},
		{"100.100.100.100/32", "100.100.100.100/32"},
		{"172.16/12", "172.16.0.0/12"},
		// Already-complete addresses without a mask are host routes.
		{"192.168.1.5", "192.168.1.5/32"},
		{"default", ""},
		{"link#24", ""},
		{"", ""},
	}
	for _, c := range cases {
		got := expandBSDNetwork(c.in)
		if got != c.want {
			t.Errorf("expandBSDNetwork(%q) = %q, want %q", c.in, got, c.want)
		}
		// Anything non-empty must be a parseable CIDR.
		if got != "" {
			if _, _, err := net.ParseCIDR(got); err != nil {
				t.Errorf("expandBSDNetwork(%q) = %q, not a valid CIDR: %v", c.in, got, err)
			}
		}
	}
}

func TestNetworkCIDR_MasksHostBits(t *testing.T) {
	// A host address plus prefix must reduce to the network address.
	ip := net.ParseIP("192.168.2.157")
	mask := net.CIDRMask(24, 32)
	if got := networkCIDR(ip, mask); got != "192.168.2.0/24" {
		t.Errorf("networkCIDR = %q, want 192.168.2.0/24", got)
	}
	// /32 (VPN point-to-point) stays as the single address.
	if got := networkCIDR(net.ParseIP("100.127.245.23"), net.CIDRMask(32, 32)); got != "100.127.245.23/32" {
		t.Errorf("networkCIDR = %q, want 100.127.245.23/32", got)
	}
}

// Locals() must never return loopback or down interfaces, and every network it
// reports must be a valid CIDR — the topology view renders these directly.
func TestLocals_RealSystemIsWellFormed(t *testing.T) {
	nets := Locals()
	for _, n := range nets {
		if n.Interface == "" {
			t.Errorf("network %+v has no interface name", n)
		}
		if _, _, err := net.ParseCIDR(n.CIDR); err != nil {
			t.Errorf("network %q is not a valid CIDR: %v", n.CIDR, err)
		}
		if ip := net.ParseIP(n.Addr); ip == nil {
			t.Errorf("addr %q is not a valid IP", n.Addr)
		}
		if ip := net.ParseIP(n.Addr); ip != nil && ip.IsLoopback() {
			t.Errorf("loopback %q must be excluded", n.Addr)
		}
	}
}
