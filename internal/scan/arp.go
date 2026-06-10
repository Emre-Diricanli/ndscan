package scan

import (
	"context"
	"net"
	"regexp"
	"strings"
)

// arpLine matches an `arp -a` row, capturing the IP and MAC.
// Example (macOS):  ? (192.168.86.44) at f0:9:d:cd:a7:1 on en0 ifscope [ethernet]
// Example (Linux):  router (192.168.1.1) at b0:6a:41:9e:2e:32 [ether] on eth0
var arpLine = regexp.MustCompile(`\(([0-9.]+)\) at ([0-9a-fA-F:]+)`)

// ARPCache reads the OS ARP table (via `arp -a -n`) and returns an IP->MAC map
// for all resolved L2 neighbors. This requires no privileges and complements
// nmap, which only reports MACs when run as root. Incomplete entries and the
// broadcast/multicast addresses are skipped. Runs through the supplied runner
// so it works locally or over SSH.
func ARPCache(ctx context.Context, runner Runner) map[string]string {
	out, err := runner.Run(ctx, "arp", "-a", "-n")
	if err != nil {
		return nil
	}
	m := map[string]string{}
	for _, ln := range strings.Split(string(out), "\n") {
		match := arpLine.FindStringSubmatch(ln)
		if match == nil {
			continue
		}
		ip, mac := match[1], normalizeMAC(match[2])
		if mac == "" || isBogusMAC(mac) {
			continue
		}
		m[ip] = mac
	}
	return m
}

// normalizeMAC pads each octet to two hex digits and lowercases, so macOS's
// zero-stripped "f0:9:d:cd:a7:1" becomes the canonical "f0:09:0d:cd:a7:01"
// that the vendor OUI database expects.
func normalizeMAC(s string) string {
	parts := strings.Split(s, ":")
	if len(parts) != 6 {
		return ""
	}
	for i, p := range parts {
		if len(p) == 0 || len(p) > 2 {
			return ""
		}
		if len(p) == 1 {
			p = "0" + p
		}
		parts[i] = strings.ToLower(p)
	}
	return strings.Join(parts, ":")
}

// MergeARPHosts adds IPs from the ARP cache that fall inside the scanned
// targets but were missed by unprivileged host discovery. Returns the combined,
// de-duplicated host list. This recovers most of what `sudo nmap` would find on
// a local subnet without needing root.
func MergeARPHosts(live []string, targets []string, arp map[string]string) []string {
	if len(arp) == 0 {
		return live
	}
	have := make(map[string]bool, len(live))
	for _, ip := range live {
		have[ip] = true
	}
	var nets []*net.IPNet
	var singles []net.IP
	for _, t := range targets {
		if _, n, err := net.ParseCIDR(t); err == nil {
			nets = append(nets, n)
		} else if ip := net.ParseIP(t); ip != nil {
			singles = append(singles, ip)
		}
	}
	// With no parseable CIDR/IP targets (e.g. a hostname), don't invent hosts.
	if len(nets) == 0 && len(singles) == 0 {
		return live
	}
	inTargets := func(ip net.IP) bool {
		for _, n := range nets {
			if n.Contains(ip) {
				return true
			}
		}
		for _, s := range singles {
			if s.Equal(ip) {
				return true
			}
		}
		return false
	}
	out := append([]string(nil), live...)
	for ipStr := range arp {
		ip := net.ParseIP(ipStr)
		if ip == nil || have[ipStr] {
			continue
		}
		if inTargets(ip) {
			out = append(out, ipStr)
			have[ipStr] = true
		}
	}
	return out
}

// isBogusMAC drops broadcast and IPv4 multicast (01:00:5e:..) entries that
// show up in the ARP table but aren't real hosts.
func isBogusMAC(mac string) bool {
	switch {
	case mac == "ff:ff:ff:ff:ff:ff":
		return true
	case strings.HasPrefix(mac, "01:00:5e"):
		return true
	case strings.HasPrefix(mac, "33:33"): // IPv6 multicast
		return true
	}
	return false
}
