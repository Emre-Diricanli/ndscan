package netinfo

import (
	"net/netip"
	"sort"
	"strconv"
	"strings"
)

// commonThirdOctets are the third-octet values most often used to number
// private VLANs and sibling subnets. A machine on 192.168.2.0/24 frequently has
// neighbours on 192.168.1.0/24 (default), 192.168.10.0/24, 192.168.100.0/24,
// and so on. Sweeping this short list finds the usual suspects without probing
// all 256 possibilities.
var commonThirdOctets = []int{0, 1, 2, 10, 20, 50, 100, 200}

// SiblingCandidates proposes routed /24 subnets to probe, given the machine's
// attached networks and any explicit CIDRs the user named.
//
// It is deliberately bounded: for each attached /24 it offers a small set of
// sibling third-octets (see commonThirdOctets) plus a few either side of the
// machine's own, rather than all 256. Explicit entries are always included and
// always win. The machine's own attached networks are never returned — there is
// nothing routed about them.
//
// The result is passive: this function sends no packets. It only decides *what*
// a later active sweep would probe.
func SiblingCandidates(locals []Network, extra []string) []string {
	attached := map[netip.Prefix]bool{}
	var bases []netip.Prefix // attached /24s to derive siblings from

	for _, l := range locals {
		p, err := netip.ParsePrefix(l.CIDR)
		if err != nil || !p.Addr().Is4() {
			continue
		}
		attached[p.Masked()] = true
		// Derive /24 siblings only from real subnets. A /32 is a single host
		// (a VPN point-to-point endpoint); the /24 around it isn't a shared
		// network, so sweeping it would be noise. Require a prefix that spans
		// more than one address but is no broader than a /24.
		if p.Bits() >= 24 && p.Bits() < 32 {
			bases = append(bases, canonical24(p.Addr()))
		}
	}

	seen := map[string]bool{}
	var out []string
	add := func(p netip.Prefix) {
		p = p.Masked()
		if attached[p] {
			return // never re-offer a network we're already on
		}
		s := p.String()
		if seen[s] {
			return
		}
		seen[s] = true
		out = append(out, s)
	}

	// Explicit user entries first: normalise a bare IP or partial to a /24.
	for _, e := range extra {
		if p, ok := parseCandidate(e); ok {
			add(p)
		}
	}

	// Derived siblings from each attached /24.
	for _, base := range bases {
		oct := base.Addr().As4()
		for _, third := range candidateThirds(int(oct[2])) {
			sib := netip.AddrFrom4([4]byte{oct[0], oct[1], byte(third), 0})
			add(netip.PrefixFrom(sib, 24))
		}
	}

	// Stable, human-friendly ordering: explicit entries keep their lead, derived
	// ones follow in numeric order.
	sort.SliceStable(out, func(i, j int) bool {
		ai, _ := netip.ParsePrefix(out[i])
		aj, _ := netip.ParsePrefix(out[j])
		return ai.Addr().Less(aj.Addr())
	})
	return out
}

// candidateThirds returns the sibling third-octet values to try for a network
// whose own third octet is `own`: the common set, plus a couple either side of
// `own`, all clamped to 0-255 and de-duplicated.
func candidateThirds(own int) []int {
	set := map[int]bool{}
	var order []int
	push := func(v int) {
		if v < 0 || v > 255 || set[v] {
			return
		}
		set[v] = true
		order = append(order, v)
	}
	for _, v := range commonThirdOctets {
		push(v)
	}
	for d := -2; d <= 2; d++ {
		push(own + d)
	}
	return order
}

// canonical24 returns the /24 prefix containing addr.
func canonical24(addr netip.Addr) netip.Prefix {
	return netip.PrefixFrom(addr, 24).Masked()
}

// parseCandidate accepts a user-supplied subnet in a few forms and returns its
// /24 prefix: "192.168.100.0/24", "192.168.100.0", or a bare "192.168.100".
func parseCandidate(s string) (netip.Prefix, bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return netip.Prefix{}, false
	}
	// Full CIDR.
	if p, err := netip.ParsePrefix(s); err == nil && p.Addr().Is4() {
		return p.Masked(), true
	}
	// Bare IPv4 address -> its /24.
	if a, err := netip.ParseAddr(s); err == nil && a.Is4() {
		return canonical24(a), true
	}
	// Partial "192.168.100" -> 192.168.100.0/24.
	if oct := strings.Split(s, "."); len(oct) == 3 {
		b := [4]byte{}
		for i := 0; i < 3; i++ {
			n, err := strconv.Atoi(oct[i])
			if err != nil || n < 0 || n > 255 {
				return netip.Prefix{}, false
			}
			b[i] = byte(n)
		}
		return netip.PrefixFrom(netip.AddrFrom4(b), 24), true
	}
	return netip.Prefix{}, false
}
