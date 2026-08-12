package scan

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type Config struct {
	Preset         string
	Ports          string
	UseSYN         bool
	Concurrency    int
	HostTimeout    time.Duration
	DisableVendors bool
	NeedMAC        bool
	// BatchSize groups targets into one nmap process. Values <=1 preserve the
	// original one-process-per-host behavior.
	BatchSize int
	// DiscardResults avoids retaining raw XML after OnResult has consumed it.
	// Streaming TUI scans use this to bound memory on large/deep scans.
	DiscardResults bool
	// Progress, if set, is called after each host finishes scanning.
	// It may be invoked from multiple goroutines.
	Progress func(done, total int)
	// OnResult, if set, is called with each host's result as soon as it
	// completes, enabling streaming consumers. May be invoked from
	// multiple goroutines.
	OnResult func(HostResult)
}

type HostResult struct {
	IP       string
	Targets  []string // all targets represented when this is a batched result
	XMLBytes []byte   // raw nmap xml for this host
	Err      error
	Fallback bool // requested SYN scan retried as TCP connect
}

// HostDiscovery uses 'nmap -sn -oG -' to find live hosts quickly, via the provided runner (local or ssh).
func HostDiscovery(ctx context.Context, targets []string, runner Runner) ([]string, error) {
	// Ensure nmap exists on the runner side (local: LookPath; ssh: rely on remote)
	if _, ok := runner.(LocalRunner); ok {
		if _, err := nmapExecutable(); err != nil {
			return nil, errors.New("nmap not found in PATH")
		}
	}

	args := []string{"-sn", "-oG", "-"}
	args = append(args, targets...)
	out, err := runner.Run(ctx, "nmap", args...)
	if err != nil {
		return nil, fmt.Errorf("host discovery failed: %w", err)
	}
	// Parse grepable lines: "Host: 192.168.86.10 ... Status: Up"
	lines := strings.Split(string(out), "\n")
	live := make([]string, 0, len(lines))
	for _, ln := range lines {
		if strings.Contains(ln, "Status: Up") {
			parts := strings.Fields(ln)
			if len(parts) >= 2 && parts[0] == "Host:" {
				live = append(live, parts[1])
			}
		}
	}
	return live, nil
}

// HostDiscoveryWithMACs performs one XML discovery sweep and returns both live
// hosts and any L2 MAC addresses nmap observed. It avoids a duplicate sweep
// when privileged or remote scans request MAC data.
func HostDiscoveryWithMACs(ctx context.Context, targets []string, runner Runner) ([]string, map[string]string, error) {
	if _, ok := runner.(LocalRunner); ok {
		if _, err := nmapExecutable(); err != nil {
			return nil, nil, errors.New("nmap not found in PATH")
		}
	}
	args := []string{"-sn", "-oX", "-"}
	args = append(args, targets...)
	xmlOut, err := runner.Run(ctx, "nmap", args...)
	if err != nil {
		return nil, nil, fmt.Errorf("host discovery failed: %w", err)
	}
	nr, err := ParseOne(xmlOut)
	if err != nil {
		return nil, nil, fmt.Errorf("host discovery parse: %w", err)
	}
	live := make([]string, 0, len(nr.Hosts))
	macs := make(map[string]string)
	for _, h := range nr.Hosts {
		if h.Status.State != "up" {
			continue
		}
		var ip, mac string
		for _, a := range h.Addresses {
			switch a.AddrType {
			case "ipv4", "ipv6":
				ip = a.Addr
			case "mac":
				mac = a.Addr
			}
		}
		if ip != "" {
			live = append(live, ip)
			if mac != "" {
				macs[ip] = mac
			}
		}
	}
	return live, macs, nil
}

// DiscoverMACs runs a lightweight discovery in XML and extracts IP->MAC pairs (same L2 only).
func DiscoverMACs(ctx context.Context, targets []string, runner Runner) (map[string]string, error) {
	_, macs, err := HostDiscoveryWithMACs(ctx, targets, runner)
	if err != nil {
		return nil, fmt.Errorf("mac discovery: %w", err)
	}
	return macs, nil
}

func ScanHosts(ctx context.Context, live []string, cfg Config, runner Runner) ([]HostResult, error) {
	if len(live) == 0 {
		return nil, nil
	}
	batchSize := cfg.BatchSize
	if batchSize < 1 {
		batchSize = 1
	}
	var batches [][]string
	for start := 0; start < len(live); start += batchSize {
		end := min(start+batchSize, len(live))
		batches = append(batches, live[start:end])
	}
	processes := (cfg.Concurrency + batchSize - 1) / batchSize
	sem := make(chan struct{}, effectiveConcurrency(processes, len(batches)))
	var wg sync.WaitGroup
	res := make([]HostResult, len(batches))
	var done int32
	// Serialises progress delivery so the reported count only ever climbs; see
	// the callback below.
	var progressMu sync.Mutex

	for i, hosts := range batches {
		wg.Add(1)
		sem <- struct{}{}
		go func(i int, hosts []string) {
			defer wg.Done()
			defer func() { <-sem }()
			xml, err := scanMany(ctx, hosts, cfg, runner)
			fallbackUsed := false
			// Some macOS configurations deny BPF/raw Ethernet handles even to
			// an elevated Homebrew nmap. Preserve useful results by retrying a
			// requested SYN scan as TCP connect; UDP has no equivalent fallback.
			if err != nil && cfg.UseSYN && rawSocketDenied(err) {
				fallback := cfg
				fallback.UseSYN = false
				xml, err = scanMany(ctx, hosts, fallback, runner)
				fallbackUsed = err == nil
			}
			result := HostResult{IP: hosts[0], Targets: append([]string(nil), hosts...), XMLBytes: xml, Err: err, Fallback: fallbackUsed}
			if !cfg.DiscardResults {
				res[i] = result
			}
			if cfg.OnResult != nil {
				cfg.OnResult(result)
			}
			if cfg.Progress != nil {
				// The counter is atomic, but the callbacks were not ordered
				// against each other: two goroutines could take 32 and 40, and
				// the one holding 32 could still deliver last, so a caller
				// watching progress saw it run backwards and settle below the
				// total. Holding the lock across the callback makes the
				// sequence monotonic, which is the only thing a progress
				// reporter is really promising.
				progressMu.Lock()
				cfg.Progress(int(atomic.AddInt32(&done, int32(len(hosts)))), len(live))
				progressMu.Unlock()
			}
		}(i, hosts)
	}
	wg.Wait()
	if cfg.DiscardResults {
		return nil, nil
	}
	return res, nil
}

// HostsUpResults synthesizes minimal "host up, no ports" results for a set of
// live IPs, for the discover-only fast path. The XML mirrors what nmap emits
// for an up host with no open ports, so the existing parsers/printers consume
// it unchanged.
func HostsUpResults(ips []string) []HostResult {
	out := make([]HostResult, 0, len(ips))
	for _, ip := range ips {
		xml := []byte(`<nmaprun><host><status state="up"/>` +
			`<address addr="` + ip + `" addrtype="ipv4"/>` +
			`<ports></ports></host></nmaprun>`)
		out = append(out, HostResult{IP: ip, XMLBytes: xml})
	}
	return out
}

func scanOne(ctx context.Context, ip string, cfg Config, runner Runner) ([]byte, error) {
	return scanMany(ctx, []string{ip}, cfg, runner)
}

func scanMany(ctx context.Context, targets []string, cfg Config, runner Runner) ([]byte, error) {
	if cfg.Preset == "smart" {
		quick := cfg
		quick.Preset = "quick"
		first, err := scanManyRaw(ctx, targets, quick, runner)
		if err != nil {
			return nil, err
		}
		nr, err := ParseOne(first)
		if err != nil {
			return nil, err
		}
		open := map[int]bool{}
		for _, host := range nr.Hosts {
			for _, port := range host.Ports.List {
				if port.State.State == "open" {
					open[port.PortID] = true
				}
			}
		}
		if len(open) == 0 {
			return first, nil
		}
		ports := make([]int, 0, len(open))
		for port := range open {
			ports = append(ports, port)
		}
		sort.Ints(ports)
		labels := make([]string, len(ports))
		for i, port := range ports {
			labels[i] = strconv.Itoa(port)
		}
		detail := cfg
		detail.Preset = "default"
		detail.Ports = strings.Join(labels, ",")
		return scanManyRaw(ctx, targets, detail, runner)
	}
	return scanManyRaw(ctx, targets, cfg, runner)
}

func scanManyRaw(ctx context.Context, targets []string, cfg Config, runner Runner) ([]byte, error) {
	// Local runner sanity check for nmap availability
	if _, ok := runner.(LocalRunner); ok {
		if _, err := nmapExecutable(); err != nil {
			return nil, errors.New("nmap not found")
		}
	}

	args := []string{"-oX", "-", "-Pn"}
	// Choose exactly one scan type. UDP is its own scan mode; otherwise use
	// SYN when requested and fall back to an unprivileged TCP connect scan.
	if cfg.Preset == "udp" {
		args = append(args, "-sU")
	} else if cfg.UseSYN {
		args = append(args, "-sS")
	} else {
		args = append(args, "-sT")
	}
	// preset (explicit --ports overrides the preset's port selection,
	// since nmap rejects -F/-p combined with a second -p)
	switch cfg.Preset {
	case "default":
		args = append(args, "-T4", "-A")
	case "udp":
		args = append(args, "-T4")
	case "deep":
		args = append(args, "-T4", "-A")
		if cfg.Ports == "" {
			args = append(args, "-p", "1-65535")
		}
	default: // "quick" and anything else
		args = append(args, "-T4")
		if cfg.Ports == "" {
			// Top 100 ports cover the vast majority of real services and scan
			// ~10x fewer ports than -F (top 1000) — a big win on firewalled
			// hosts where each unanswered port costs a timeout.
			args = append(args, "--top-ports", "100")
		}
	}
	// explicit ports override
	if cfg.Ports != "" {
		args = append(args, "-p", cfg.Ports)
	}
	// per-host timeout for speed
	if cfg.HostTimeout > 0 {
		args = append(args, "--host-timeout", cfg.HostTimeout.String())
	}

	// Timing: the deep/default presets keep nmap's conservative retries so
	// version/OS detection stays accurate. Quick/udp scans (typically on a
	// LAN) go aggressive — no retries, high min-rate — which roughly halves
	// per-host time on firewalled hosts with negligible accuracy loss.
	if cfg.Preset == "default" || cfg.Preset == "deep" {
		args = append(args, "--max-retries", "2", "--min-rate", "200")
	} else {
		args = append(args, "--max-retries", "0", "--min-rate", "1000")
	}

	args = append(args, targets...)
	return runner.Run(ctx, "nmap", args...)
}

func rawSocketDenied(err error) bool {
	s := strings.ToLower(err.Error())
	return strings.Contains(s, "operation not permitted") &&
		(strings.Contains(s, "raw socket") || strings.Contains(s, "eth handle") || strings.Contains(s, "dnet"))
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// effectiveConcurrency picks the worker count for a scan: the requested cap,
// but never more workers than there are hosts (no idle workers on small
// scans). The requested value is honored as-is otherwise, so users can raise
// it for big ranges or lower it to be gentle.
func effectiveConcurrency(requested, hosts int) int {
	want := max(1, requested)
	if want > hosts {
		want = hosts
	}
	return max(1, want)
}
