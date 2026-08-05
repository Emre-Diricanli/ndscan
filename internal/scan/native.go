package scan

import (
	"context"

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
	})
	return sweep.IPs(res), sweep.MACs(res), nil
}

// NativeDiscoverySupported reports whether native discovery makes sense for
// this runner. It requires probing from the local machine, so an SSH runner
// (which would probe the wrong network) is excluded.
func NativeDiscoverySupported(runner Runner) bool {
	_, local := runner.(LocalRunner)
	return local
}
