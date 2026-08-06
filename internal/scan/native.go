package scan

import (
	"context"
	"net/netip"

	"github.com/Emre-Diricanli/ndscan/internal/netinfo"
	"github.com/Emre-Diricanli/ndscan/internal/sweep"
)

// NativeDiscovery finds live hosts without invoking nmap, using the ARP cache
// plus a bounded TCP connect sweep (see package sweep). It mirrors
// HostDiscoveryWithMACs so callers can swap between the two.
//
// On a LAN this is typically an order of magnitude faster than `nmap -sn`,
// because the timeout policy is ours rather than nmap's WAN-tuned defaults, and
// because the ARP cache answers for free. It needs no root.
//
// The runner is used only for the ARP read, so this still works over SSH.
// Note the TCP probes originate from *this* machine even when a runner points
// elsewhere, so native discovery is meant for local scans; callers scanning via
// SSH should stay on the nmap path.
func NativeDiscovery(ctx context.Context, targets []string, runner Runner, progress func(done, total int)) ([]string, map[string]string, error) {
	res := sweep.Run(ctx, targets, sweep.Config{
		ARP: func(c context.Context) map[string]string {
			return ARPCache(c, runner)
		},
		Progress: progress,
		Attached: targetsAreAttached(targets),
	})
	return sweep.IPs(res), sweep.MACs(res), nil
}

// targetsAreAttached reports whether every target lies inside a network this
// machine has an interface on.
//
// It gates the sweep's L2 shortcuts, so it must be conservative: one routed
// target among the set disables them for the whole scan, because a TCP reset
// from beyond a router might have come from a middlebox rather than the host,
// and the ARP cache can only ever speak for the local segment.
func targetsAreAttached(targets []string) bool {
	locals := netinfo.Locals()
	if len(locals) == 0 || len(targets) == 0 {
		return false
	}
	nets := make([]netip.Prefix, 0, len(locals))
	for _, l := range locals {
		if p, err := netip.ParsePrefix(l.CIDR); err == nil {
			nets = append(nets, p)
		}
	}
	if len(nets) == 0 {
		return false
	}

	within := func(p netip.Prefix) bool {
		for _, n := range nets {
			// Both endpoints inside one local network implies the whole range
			// is, since a prefix can't straddle a boundary without containing it.
			if n.Overlaps(p) && n.Bits() <= p.Bits() {
				return true
			}
		}
		return false
	}

	for _, t := range targets {
		if a, err := netip.ParseAddr(t); err == nil {
			if !within(netip.PrefixFrom(a, a.BitLen())) {
				return false
			}
			continue
		}
		p, err := netip.ParsePrefix(t)
		if err != nil || !within(p.Masked()) {
			return false
		}
	}
	return true
}

// NativeDiscoverySupported reports whether native discovery makes sense for
// this runner. It requires probing from the local machine, so an SSH runner
// (which would probe the wrong network) is excluded.
func NativeDiscoverySupported(runner Runner) bool {
	_, local := runner.(LocalRunner)
	return local
}
