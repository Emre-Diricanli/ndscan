package scan

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
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
	XMLBytes []byte // raw nmap xml for this host
	Err      error
}

// HostDiscovery uses 'nmap -sn -oG -' to find live hosts quickly, via the provided runner (local or ssh).
func HostDiscovery(ctx context.Context, targets []string, runner Runner) ([]string, error) {
	// Ensure nmap exists on the runner side (local: LookPath; ssh: rely on remote)
	if _, ok := runner.(LocalRunner); ok {
		if _, err := exec.LookPath("nmap"); err != nil {
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

// DiscoverMACs runs a lightweight discovery in XML and extracts IP->MAC pairs (same L2 only).
func DiscoverMACs(ctx context.Context, targets []string, runner Runner) (map[string]string, error) {
	if _, ok := runner.(LocalRunner); ok {
		if _, err := exec.LookPath("nmap"); err != nil {
			return nil, errors.New("nmap not found in PATH")
		}
	}
	args := []string{"-sn", "-oX", "-"}
	args = append(args, targets...)
	xmlOut, err := runner.Run(ctx, "nmap", args...)
	if err != nil {
		return nil, fmt.Errorf("mac discovery failed: %w", err)
	}
	nr, err := ParseOne(xmlOut)
	if err != nil {
		return nil, fmt.Errorf("mac discovery parse: %w", err)
	}
	m := make(map[string]string, len(nr.Hosts))
	for _, h := range nr.Hosts {
		var ip, mac string
		for _, a := range h.Addresses {
			switch a.AddrType {
			case "ipv4", "ipv6":
				ip = a.Addr
			case "mac":
				mac = a.Addr
			}
		}
		if ip != "" && mac != "" {
			m[ip] = mac
		}
	}
	return m, nil
}

func ScanHosts(ctx context.Context, live []string, cfg Config, runner Runner) ([]HostResult, error) {
	if len(live) == 0 {
		return nil, nil
	}
	sem := make(chan struct{}, effectiveConcurrency(cfg.Concurrency, len(live)))
	var wg sync.WaitGroup
	res := make([]HostResult, len(live))
	var done int32

	for i, ip := range live {
		wg.Add(1)
		sem <- struct{}{}
		go func(i int, host string) {
			defer wg.Done()
			defer func() { <-sem }()
			xml, err := scanOne(ctx, host, cfg, runner)
			res[i] = HostResult{IP: host, XMLBytes: xml, Err: err}
			if cfg.OnResult != nil {
				cfg.OnResult(res[i])
			}
			if cfg.Progress != nil {
				cfg.Progress(int(atomic.AddInt32(&done, 1)), len(live))
			}
		}(i, ip)
	}
	wg.Wait()
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
	// Local runner sanity check for nmap availability
	if _, ok := runner.(LocalRunner); ok {
		if _, err := exec.LookPath("nmap"); err != nil {
			return nil, errors.New("nmap not found")
		}
	}

	args := []string{"-oX", "-", "-Pn"}
	// choose scan type
	if cfg.UseSYN {
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
		args = append(args, "-sU", "-T4")
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

	args = append(args, ip)
	return runner.Run(ctx, "nmap", args...)
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
