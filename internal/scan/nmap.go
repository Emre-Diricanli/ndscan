package scan

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"sync"
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
	sem := make(chan struct{}, max(1, cfg.Concurrency))
	var wg sync.WaitGroup
	res := make([]HostResult, len(live))

	for i, ip := range live {
		wg.Add(1)
		sem <- struct{}{}
		go func(i int, host string) {
			defer wg.Done()
			defer func() { <-sem }()
			xml, err := scanOne(ctx, host, cfg, runner)
			res[i] = HostResult{IP: host, XMLBytes: xml, Err: err}
		}(i, ip)
	}
	wg.Wait()
	return res, nil
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
	// preset
	switch cfg.Preset {
	case "quick":
		args = append(args, "-T4", "-F")
	case "default":
		args = append(args, "-T4", "-A")
	case "udp":
		args = append(args, "-sU", "-T4")
	case "deep":
		args = append(args, "-T4", "-p", "1-65535", "-A")
	default:
		args = append(args, "-T4", "-F")
	}
	// explicit ports override
	if cfg.Ports != "" {
		args = append(args, "-p", cfg.Ports)
	}
	// per-host timeout for speed
	if cfg.HostTimeout > 0 {
		args = append(args, "--host-timeout", cfg.HostTimeout.String())
	}
	// fewer retries for speed
	args = append(args, "--max-retries", "1", "--min-rate", "200")

	args = append(args, ip)
	return runner.Run(ctx, "nmap", args...)
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
