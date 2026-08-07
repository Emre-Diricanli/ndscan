package engine

import (
	"context"
	"sort"
	"sync"
	"time"

	"github.com/Emre-Diricanli/ndscan/internal/enrich"
	"github.com/Emre-Diricanli/ndscan/internal/scan"
	"github.com/Emre-Diricanli/ndscan/internal/ui"
	"github.com/Emre-Diricanli/ndscan/internal/vendor"
)

// discover finds live hosts and the MAC addresses we can learn for free.
//
// It returns whether the native sweep ran, because that is not simply
// Plan.Fast: native discovery is unavailable over SSH, where the probes would
// originate from the wrong machine.
func (e *Engine) discover(ctx context.Context, p Plan, runner scan.Runner, emit Emit) (
	live []string, macs map[string]string, rtts map[string]time.Duration, fast bool, t Timings, err error,
) {
	emit.phase(PhaseDiscover, 0, 0)
	discoveryStart := time.Now()

	// The extra nmap -sn MAC sweep only beats the ARP cache when it can see
	// something the cache cannot: as root locally (a real ARP scan), or over
	// SSH, where we cannot introspect the remote host's privileges. A local
	// unprivileged pass just duplicates ARP data at the cost of a whole sweep.
	nmapMACWorthwhile := p.SSHTarget != "" || scan.IsRoot()

	var discoveredMACs map[string]string
	switch {
	case p.Fast && scan.NativeDiscoverySupported(runner):
		// Native ARP + TCP sweep: no nmap, no root, and roughly 15-20x faster
		// than `nmap -sn` on a LAN because the timeout policy is ours.
		fast = true
		live, discoveredMACs, rtts, err = scan.NativeDiscoveryTimed(ctx, p.Targets, runner,
			func(done, total int) { emit.phase(PhaseDiscover, done, total) })
	case p.ShowMAC && nmapMACWorthwhile:
		emit.phase(PhaseMAC, 0, 0)
		live, discoveredMACs, err = scan.HostDiscoveryWithMACs(ctx, p.Targets, runner)
	default:
		live, err = scan.HostDiscovery(ctx, p.Targets, runner)
	}
	if err != nil {
		return nil, nil, nil, fast, t, err
	}
	// Native discovery reports cancellation by returning early rather than by
	// erroring, so the context is checked directly — otherwise a cancelled scan
	// would be reported as a completed one.
	if ctx.Err() != nil {
		return nil, nil, nil, fast, t, nil
	}
	t.Discovery = time.Since(discoveryStart)

	enrichmentStart := time.Now()
	// The ARP cache is always worth reading: it recovers neighbours and MACs
	// that unprivileged nmap misses, and it costs nothing.
	arp := scan.ARPCache(ctx, runner)
	live = scan.MergeARPHosts(live, p.Targets, arp)

	macs = map[string]string{}
	if p.ShowMAC && nmapMACWorthwhile {
		for ip, mac := range discoveredMACs {
			macs[ip] = mac
		}
	}
	for ip, mac := range arp {
		if _, ok := macs[ip]; !ok {
			macs[ip] = mac
		}
	}
	t.Enrichment = time.Since(enrichmentStart)

	return live, macs, rtts, fast, t, nil
}

// scanPorts probes the live hosts and accumulates rows onto the outcome.
//
// Rows stream through emit as each host resolves rather than arriving in one
// batch at the end, so a front end can draw a host the moment it is known
// instead of waiting for the slowest address in the scan to finish timing out.
func (e *Engine) scanPorts(
	ctx context.Context, p Plan, runner scan.Runner,
	live []string, macs map[string]string, rtts map[string]time.Duration,
	emit Emit, out *Outcome,
) {
	if p.DiscoverOnly {
		// Discover-only still produces rows, just without port data, so every
		// downstream renderer sees the same shape it always does.
		out.Rows = ui.BuildRows(scan.HostsUpResults(live), nil, p.ShowMAC, p.ShowVendors, macs)
		emit.rows(out.Rows)
		return
	}

	var oui vendor.DB
	if p.ShowMAC && p.ShowVendors {
		oui = vendor.LoadDefault()
	}

	portStart := time.Now()
	native := scan.NativePortScanViable(scan.Config{
		Preset: p.Preset, Ports: p.Ports, UseSYN: p.RootScan,
		Concurrency: p.Concurrency, HostTimeout: p.HostTimeout,
	}, runner)
	emit.scanPhase(0, len(live), native)

	var (
		mu      sync.Mutex
		rows    []ui.Row
		failed  int
		firstEr error
		fbacks  int
	)
	cfg := scan.Config{
		Preset:         p.Preset,
		Ports:          p.Ports,
		UseSYN:         p.RootScan,
		Concurrency:    p.Concurrency,
		HostTimeout:    p.HostTimeout,
		DisableVendors: !(p.ShowMAC && p.ShowVendors),
		NeedMAC:        p.ShowMAC,
		BatchSize:      16,
		// The raw XML is consumed by OnResult as each host lands, so retaining
		// it would only grow memory across a large or deep scan.
		DiscardResults: true,
		Progress:       func(done, total int) { emit.scanPhase(done, total, native) },
		OnResult: func(r scan.HostResult) {
			// ScanHosts reports per-host failures through HostResult.Err rather
			// than through its returned error, so a run can lose hosts and
			// still look like it succeeded. Counting them here is what lets the
			// outcome say "partial" instead of presenting a short list as the
			// whole network.
			if r.Err != nil {
				mu.Lock()
				// A cancelled scan errors on every outstanding host. Those are
				// consequences of the cancellation, not independent failures,
				// and counting them would report a cancelled run as a badly
				// broken one.
				if ctx.Err() == nil {
					failed += maxInt(1, len(r.Targets))
					if firstEr == nil {
						firstEr = r.Err
					}
				}
				mu.Unlock()
				return
			}
			if r.Fallback {
				mu.Lock()
				fbacks += maxInt(1, len(r.Targets))
				mu.Unlock()
			}
			built := ui.BuildRows([]scan.HostResult{r}, oui, p.ShowMAC, p.ShowVendors, macs)
			if len(built) == 0 {
				return
			}
			mu.Lock()
			rows = append(rows, built...)
			mu.Unlock()
			emit.rows(built)
		},
	}

	if native {
		// Native connect scan: far faster than shelling out to nmap for the
		// same port set, because every probe runs concurrently under one
		// timeout policy. The returned slice is discarded because OnResult has
		// already delivered every row.
		// The discovery sweep already timed each host's answer; passing it
		// through here is what puts a value in the RTT column on the fast path.
		meta := make(map[string]scan.NativeMetadata, len(rtts))
		for ip, d := range rtts {
			meta[ip] = scan.NativeMetadata{RTT: d}
		}
		scan.NativePortScanWithMetadata(ctx, live, meta, cfg, func(done, total int) {
			emit.scanPhase(done, total, true)
		})
	} else if _, err := scan.ScanHosts(ctx, live, cfg, runner); err != nil {
		mu.Lock()
		if firstEr == nil {
			firstEr = err
		}
		mu.Unlock()
	}

	mu.Lock()
	out.Rows = append(out.Rows, rows...)
	out.Failed = failed
	out.FirstErr = firstEr
	out.Fallbacks = fbacks
	mu.Unlock()
	out.Timings.Ports = time.Since(portStart)
}

// enrich fills in hostnames via reverse DNS.
//
// It runs last because the rows are already on screen by then, so it fills a
// column rather than delaying anything. A miss just leaves the field blank.
func (e *Engine) enrich(ctx context.Context, p Plan, emit Emit, out *Outcome) {
	if len(out.Rows) == 0 {
		return
	}
	emit.phase(PhaseEnrich, 0, len(out.Rows))
	ips := make([]string, 0, len(out.Rows))
	for _, r := range out.Rows {
		ips = append(ips, r.IP)
	}

	// Multicast discovery first, because ApplyHostnames only fills a name that
	// is still empty and the best name should get there first. A device that
	// advertises itself as "Living-Room-TV" is telling us what it is; a PTR
	// record, where one exists at all, usually just spells the address back.
	//
	// Both passes are opt-in per plan and strictly bounded, so a network where
	// nothing answers costs their timeout and nothing else.
	if p.Multicast {
		ui.ApplyHostnames(out.Rows, e.multicastNames(ctx))
	}
	ui.ApplyHostnames(out.Rows, enrich.LookupPTR(ctx, ips, enrich.Config{}))
	// These rows were already delivered by the port scan; enrichment only filled
	// in a column. Re-announcing them as arrivals would duplicate every host in
	// a front end that appends.
	emit.rowsUpdated(out.Rows)
}

// multicastNames asks the network what it calls itself, reusing a recent answer
// rather than asking again.
//
// A discovery pass costs seconds of listening, and watch mode rescans every 60
// — paying that every interval would make the scan mostly waiting, to re-learn
// names that change on the order of days. The cache is per-Engine, so a
// long-lived process shares it while each CLI invocation starts fresh.
func (e *Engine) multicastNames(ctx context.Context) map[string]string {
	e.mcMu.Lock()
	defer e.mcMu.Unlock()

	if e.mcNames != nil && e.now().Sub(e.mcAt) < multicastTTL {
		return e.mcNames
	}
	names := enrich.LookupMDNS(ctx, enrich.MDNSConfig{})
	for ip, label := range enrich.LookupSSDP(ctx, enrich.SSDPConfig{}) {
		if _, ok := names[ip]; !ok {
			names[ip] = label // mDNS names are friendlier; SSDP fills gaps
		}
	}
	// A pass that found nothing is not cached: the usual cause is a transient
	// network condition, and remembering the emptiness would extend a momentary
	// failure into minutes of blank names.
	if len(names) > 0 {
		e.mcNames, e.mcAt = names, e.now()
	}
	return names
}

func sortRows(rows []ui.Row) {
	sort.Slice(rows, func(i, j int) bool { return ui.IPLess(rows[i].IP, rows[j].IP) })
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}
