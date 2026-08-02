// Package netinfo reports the networks this machine is attached to, and the
// default gateway, by reading interface addresses and the OS routing table.
//
// This is deliberately passive: it sends no packets and needs no privileges, so
// it can populate the topology view instantly and truthfully. It only knows
// about networks this host is *on* — it cannot see subnets beyond the gateway.
// Discovering those requires active probing (traceroute or scanning a guessed
// range), which is a separate, opt-in concern.
package netinfo

import (
	"context"
	"net"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

// Network is one IPv4 network this machine has an address on.
type Network struct {
	Interface string // e.g. "en0", "utun8"
	CIDR      string // e.g. "192.168.2.0/24"
	Addr      string // this machine's address on that network
}

// Gateway is the default next hop, when one exists.
type Gateway struct {
	IP        string // e.g. "192.168.1.1"
	Interface string // e.g. "en0"
}

// Locals returns every non-loopback IPv4 network this machine is attached to,
// in interface order. Interfaces that are down are skipped.
func Locals() []Network {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil
	}
	var out []Network
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			ipn, ok := a.(*net.IPNet)
			if !ok || ipn.IP.To4() == nil || ipn.IP.IsLoopback() {
				continue
			}
			out = append(out, Network{
				Interface: iface.Name,
				CIDR:      networkCIDR(ipn.IP, ipn.Mask),
				Addr:      ipn.IP.String(),
			})
		}
	}
	return out
}

// networkCIDR renders the network address for ip/mask, e.g. 192.168.2.157 with
// a /24 mask becomes "192.168.2.0/24".
func networkCIDR(ip net.IP, mask net.IPMask) string {
	ones, _ := mask.Size()
	return ip.Mask(mask).String() + "/" + strconv.Itoa(ones)
}

// DefaultGateway returns the default next hop, or a zero Gateway if there is
// none (or the routing table can't be read). Best-effort and non-fatal: the
// topology view simply omits the gateway when this comes back empty.
func DefaultGateway() Gateway {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "netstat", "-rn", "-f", "inet").Output()
	if err != nil {
		// Linux systems without netstat may still have `ip route`.
		out, err = exec.CommandContext(ctx, "ip", "route").Output()
		if err != nil {
			return Gateway{}
		}
	}
	ip, iface := parseDefaultGateway(string(out))
	return Gateway{IP: ip, Interface: iface}
}

// parseDefaultGateway extracts the default route's next-hop IP and interface
// from routing-table text. It handles BSD/macOS `netstat -rn`, Linux
// `netstat -rn`, and `ip route` forms.
//
// Rows whose gateway is a link reference rather than an address (macOS prints
// "link#24" for VPN tunnels) are skipped: they name an interface, not a next
// hop we can draw or probe.
func parseDefaultGateway(routes string) (ip, iface string) {
	for _, ln := range strings.Split(routes, "\n") {
		fields := strings.Fields(ln)
		if len(fields) < 2 {
			continue
		}
		// `ip route` form: "default via 10.0.0.1 dev eth0 ..."
		if fields[0] == "default" && len(fields) >= 4 && fields[1] == "via" {
			if net.ParseIP(fields[2]) != nil {
				gw := fields[2]
				dev := ""
				for i := 3; i+1 < len(fields); i++ {
					if fields[i] == "dev" {
						dev = fields[i+1]
						break
					}
				}
				return gw, dev
			}
			continue
		}
		// netstat form: destination is "default" (BSD) or "0.0.0.0" (Linux),
		// gateway is the second column, interface is the last.
		if fields[0] != "default" && fields[0] != "0.0.0.0" {
			continue
		}
		if net.ParseIP(fields[1]) == nil {
			continue // e.g. "link#24" — not a usable next hop
		}
		// A 0.0.0.0 gateway on Linux means "on-link", not a next hop.
		if fields[1] == "0.0.0.0" {
			continue
		}
		return fields[1], fields[len(fields)-1]
	}
	return "", ""
}

// expandBSDNetwork turns an abbreviated BSD route destination into a canonical
// CIDR: "10.11/16" -> "10.11.0.0/16", "127" -> "127.0.0.0/8". Values that
// aren't networks ("default", "link#24") return "".
//
// Exported behavior is covered by tests; kept here because only route parsing
// needs it.
func expandBSDNetwork(dest string) string {
	if dest == "" || dest == "default" || strings.HasPrefix(dest, "link#") {
		return ""
	}
	addr, maskStr, hasMask := strings.Cut(dest, "/")
	octets := strings.Split(addr, ".")
	if len(octets) > 4 {
		return ""
	}
	for _, o := range octets {
		if o == "" {
			return ""
		}
		if n, err := strconv.Atoi(o); err != nil || n < 0 || n > 255 {
			return ""
		}
	}
	// BSD omits trailing zero octets; pad them back.
	full := append([]string(nil), octets...)
	for len(full) < 4 {
		full = append(full, "0")
	}
	ipStr := strings.Join(full, ".")
	if net.ParseIP(ipStr) == nil {
		return ""
	}
	if !hasMask {
		// No mask: BSD implies a classful width from the octets present, and a
		// complete dotted quad is a host route.
		bits := len(octets) * 8
		if len(octets) == 4 {
			bits = 32
		}
		maskStr = strconv.Itoa(bits)
	}
	ones, err := strconv.Atoi(maskStr)
	if err != nil || ones < 0 || ones > 32 {
		return ""
	}
	ip := net.ParseIP(ipStr).To4()
	if ip == nil {
		return ""
	}
	return ip.Mask(net.CIDRMask(ones, 32)).String() + "/" + strconv.Itoa(ones)
}
