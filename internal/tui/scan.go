package tui

import (
	"context"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/Emre-Diricanli/ndscan/internal/config"
	"github.com/Emre-Diricanli/ndscan/internal/scan"
	"github.com/Emre-Diricanli/ndscan/internal/ui"
	"github.com/Emre-Diricanli/ndscan/internal/vendor"
)

// scanParams is the resolved configuration captured from the form.
type scanParams struct {
	sshTarget   string
	targets     []string
	preset      string
	ports       string
	showMac     bool
	showVendors bool
	rootScan    bool
	concurrency int
	hostTimeout time.Duration
}

// ----- messages streamed from the scan goroutine into the Bubble Tea loop -----

type phaseMsg struct {
	phase string // "discover" | "mac" | "scan"
	done  int
	total int
}

// hostRowMsg carries one host's parsed rows the moment its scan finishes.
type hostRowMsg struct {
	rows []ui.Row
}

type doneMsg struct {
	rows      []ui.Row
	failed    int
	elapsed   time.Duration
	cancelled bool
	diff      map[string]config.HostDiff
	timings   phaseTimings
	firstErr  error
	fallbacks int
}

type phaseTimings struct {
	discovery  time.Duration
	enrichment time.Duration
	ports      time.Duration
}

type errMsg struct{ err error }

// listen blocks on the event channel and forwards the next message into the
// Bubble Tea runtime. It is re-issued from Update until a terminal message
// (doneMsg / errMsg) arrives.
func listen(ch <-chan tea.Msg) tea.Cmd {
	return func() tea.Msg { return <-ch }
}

// nmapAvailable reports whether a scan can proceed for the given SSH target
// ("" = locally). Remote availability is left to the SSH side to report.
//
// Local scans no longer require nmap: discovery and the quick-preset port scan
// both run natively (see internal/sweep). nmap is only needed for the presets
// that use its fingerprinting, so its absence must not block a scan outright.
func nmapAvailable(sshTarget string) bool {
	// Remote: the SSH side reports its own missing-nmap error.
	// Local: the native scanner handles discovery and quick port scans, so a
	// missing nmap only limits the fingerprinting presets, not scanning itself.
	return true
}

// runScan launches the scan in a background goroutine, returning the channel
// that progress and result messages are delivered on, plus a cancel func.
func runScan(p scanParams) (<-chan tea.Msg, context.CancelFunc) {
	ch := make(chan tea.Msg, 64)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)

	go func() {
		defer close(ch)
		defer cancel()
		start := time.Now()
		var timings phaseTimings
		var firstScanErr error
		fallbacks := 0
		var runner scan.Runner
		if p.sshTarget != "" {
			runner = scan.NewRunner(p.sshTarget)
		} else {
			runner = scan.NewLocalRunner()
		}

		finish := func(rows []ui.Row, failed int, cancelled bool) {
			prev := config.LoadHistory(p.targets, p.ports, p.preset)
			cur := make([]config.HostSnapshot, 0, len(rows))
			for _, r := range rows {
				cur = append(cur, config.HostSnapshot{IP: r.IP, Host: r.Host, Ports: r.Ports})
			}
			var diff map[string]config.HostDiff
			if !cancelled && failed == 0 { // failed/partial scans must not poison history
				diff = config.Diff(prev, cur)
				_ = config.SaveHistory(p.targets, p.ports, p.preset, cur)
			}
			ch <- doneMsg{
				rows:      rows,
				failed:    failed,
				elapsed:   time.Since(start),
				cancelled: cancelled,
				diff:      diff,
				timings:   timings,
				firstErr:  firstScanErr,
				fallbacks: fallbacks,
			}
		}

		ch <- phaseMsg{phase: "discover"}
		discoveryStart := time.Now()
		nmapMACWorthwhile := p.sshTarget != "" || scan.IsRoot()
		var live []string
		var discoveredMACs map[string]string
		var err error
		switch {
		case scan.NativeDiscoverySupported(runner):
			// Native ARP + TCP sweep: no nmap, no root, and roughly 15-20x
			// faster than `nmap -sn` on a LAN because the timeout policy is
			// ours. Only valid locally — over SSH the probes would originate
			// from the wrong machine.
			live, discoveredMACs, err = scan.NativeDiscovery(ctx, p.targets, runner,
				func(done, total int) {
					// Non-blocking: the sweep fans out across thousands of
					// goroutines, and a full channel (or a cancelled scan whose
					// reader has stopped) must never stall them.
					select {
					case ch <- phaseMsg{phase: "discover", done: done, total: total}:
					default:
					}
				})
		case p.showMac && nmapMACWorthwhile:
			live, discoveredMACs, err = scan.HostDiscoveryWithMACs(ctx, p.targets, runner)
		default:
			live, err = scan.HostDiscovery(ctx, p.targets, runner)
		}
		if err != nil {
			if ctx.Err() != nil {
				finish(nil, 0, true)
				return
			}
			ch <- errMsg{err}
			return
		}
		// Native discovery reports cancellation by returning early rather than
		// by erroring, so check the context directly — otherwise a cancelled
		// scan would be reported as a completed one.
		if ctx.Err() != nil {
			finish(nil, 0, true)
			return
		}
		timings.discovery = time.Since(discoveryStart)

		// ARP-cache fallback: recover neighbors and MACs that unprivileged
		// nmap misses. Always read it — MACs are free and require no root.
		enrichmentStart := time.Now()
		arpMap := scan.ARPCache(ctx, runner)
		live = scan.MergeARPHosts(live, p.targets, arpMap)

		if len(live) == 0 {
			finish(nil, 0, false)
			return
		}

		// Build the MAC map. The ARP cache already covers every L2 neighbor
		// for free, so we only run the extra nmap -sn MAC sweep when it can do
		// better: as root locally (a real ARP scan), or over SSH (the remote
		// host's privileges/cache, which we can't introspect from here).
		// A local unprivileged nmap pass just duplicates the ARP data at the
		// cost of a whole extra sweep, so we skip it.
		macMap := map[string]string{}
		if p.showMac && nmapMACWorthwhile {
			for ip, mac := range discoveredMACs {
				macMap[ip] = mac
			}
		}
		for ip, mac := range arpMap {
			if _, ok := macMap[ip]; !ok {
				macMap[ip] = mac
			}
		}

		var oui vendor.DB
		if p.showMac && p.showVendors {
			oui = vendor.LoadDefault()
		}
		timings.enrichment = time.Since(enrichmentStart)

		// Stream each host's parsed rows as its scan completes.
		var mu sync.Mutex
		var streamed []ui.Row
		failed := 0
		cfg := scan.Config{
			Preset:         p.preset,
			Ports:          p.ports,
			UseSYN:         p.rootScan,
			Concurrency:    p.concurrency,
			HostTimeout:    p.hostTimeout,
			DisableVendors: !(p.showMac && p.showVendors),
			NeedMAC:        p.showMac,
			BatchSize:      16,
			DiscardResults: true,
			Progress: func(done, total int) {
				ch <- phaseMsg{phase: "scan", done: done, total: total}
			},
			OnResult: func(r scan.HostResult) {
				if r.Err != nil {
					mu.Lock()
					if ctx.Err() == nil {
						failed += maxInt(1, len(r.Targets))
						if firstScanErr == nil {
							firstScanErr = r.Err
						}
					}
					mu.Unlock()
					return
				}
				if r.Fallback {
					mu.Lock()
					fallbacks += maxInt(1, len(r.Targets))
					mu.Unlock()
				}
				rows := ui.BuildRows([]scan.HostResult{r}, oui, p.showMac, p.showVendors, macMap)
				if len(rows) == 0 {
					return
				}
				mu.Lock()
				streamed = append(streamed, rows...)
				mu.Unlock()
				ch <- hostRowMsg{rows: rows}
			},
		}
		ch <- phaseMsg{phase: "scan", done: 0, total: len(live)}

		portStart := time.Now()
		if scan.NativePortScanViable(cfg, runner) {
			// Native connect scan: ~70x faster than shelling out to nmap for
			// the same port set, because every probe runs concurrently under one
			// timeout policy. cfg.OnResult fires as each host finishes, so rows
			// appear while the slowest addresses are still timing out — the
			// returned slice is deliberately discarded, since consuming it would
			// mean waiting for exactly that laggard before drawing anything.
			scan.NativePortScan(ctx, live, cfg, func(done, total int) {
				select {
				case ch <- phaseMsg{phase: "scan", done: done, total: total}:
				default:
				}
			})
		} else {
			_, err = scan.ScanHosts(ctx, live, cfg, runner)
		}
		timings.ports = time.Since(portStart)
		mu.Lock()
		rows := append([]ui.Row(nil), streamed...)
		nFailed := failed
		mu.Unlock()

		if ctx.Err() != nil {
			finish(rows, nFailed, true)
			return
		}
		if err != nil {
			ch <- errMsg{err}
			return
		}
		finish(rows, nFailed, false)
	}()

	return ch, cancel
}

// parseTargets splits a raw target string, peeling off a leading "user@host"
// SSH jump target if present.
func parseTargets(raw string) (sshTarget string, targets []string) {
	fields := strings.Fields(raw)
	if len(fields) == 0 {
		return "", nil
	}
	if strings.Contains(fields[0], "@") && !strings.Contains(fields[0], "/") {
		return fields[0], fields[1:]
	}
	return "", fields
}

// localCIDR guesses the primary local IPv4 network (e.g. "192.168.1.0/24")
// for prefilling the targets field. Returns "" if none found.
func localCIDR() string {
	ifaces, err := net.Interfaces()
	if err != nil {
		return ""
	}
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
			if !ok || ipn.IP.To4() == nil {
				continue
			}
			ones, _ := ipn.Mask.Size()
			return ipn.IP.Mask(ipn.Mask).String() + "/" + strconv.Itoa(ones)
		}
	}
	return ""
}
