package scan

import (
	"context"
	"encoding/xml"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/Emre-Diricanli/ndscan/internal/sweep"
)

var scanNativePorts = sweep.ScanPorts

// NativePortScan probes open ports on the given hosts without invoking nmap,
// returning results in the same shape the nmap path produces so every existing
// parser, printer, and report renderer consumes them unchanged.
//
// It is dramatically faster than nmap for the common "what's open here" case,
// but it reports port numbers and well-known service names only — no version
// detection, OS fingerprinting, or NSE output. Callers needing those must use
// the nmap path (the deep/default presets).
//
// progress may be nil. When set it is called from multiple goroutines as hosts
// complete, so it must be safe for concurrent use.
//
// cfg.OnResult, when set, receives each host the instant it finishes probing
// rather than after every host has. Callers should prefer it over the returned
// slice: the slice can only be complete once the slowest unreachable address has
// burned its full timeout, whereas a responsive LAN host streams in
// milliseconds. The returned slice is still complete, for callers that only want
// the final answer.
func NativePortScan(ctx context.Context, hosts []string, cfg Config, progress func(done, total int)) []HostResult {
	ports, err := parsePortSpec(cfg.Ports)
	if err != nil {
		out := make([]HostResult, 0, len(hosts))
		for i, host := range hosts {
			result := HostResult{IP: host, Err: err}
			out = append(out, result)
			if cfg.OnResult != nil {
				cfg.OnResult(result)
			}
			if progress != nil {
				progress(i+1, len(hosts))
			}
		}
		return out
	}

	var onResult func(sweep.PortResult)
	if cfg.OnResult != nil {
		onResult = func(r sweep.PortResult) {
			cfg.OnResult(HostResult{IP: r.IP, XMLBytes: syntheticXML(r)})
		}
	}

	var incomplete int
	results := scanNativePorts(ctx, hosts, sweep.PortConfig{
		Ports:       ports,
		Concurrency: cfg.Concurrency * 32, // per-host workers -> per-probe workers
		Progress:    progress,
		OnResult:    onResult,
		OnIncomplete: func(probes int) {
			incomplete = probes
		},
	})

	out := make([]HostResult, 0, len(results))
	for _, r := range results {
		out = append(out, HostResult{
			IP:       r.IP,
			XMLBytes: syntheticXML(r),
		})
	}
	// Descriptor exhaustion is a property of the run, not of any one host: every
	// host's ports are a floor rather than a full answer. Marking each result as
	// failed would say something different and worse — that those hosts were not
	// scanned at all — and callers that count failures would then discard a set
	// of results that is incomplete but still entirely valid. One extra entry
	// carries the run-level fact without libelling the individual hosts.
	if err := incompleteError(incomplete); err != nil {
		out = append(out, HostResult{Err: err})
	}
	return out
}

// syntheticXML renders a native port result as the subset of nmap's XML that
// ndscan's parser reads. Values are escaped so a hostile service name or
// address can't produce malformed output.
func syntheticXML(r sweep.PortResult) []byte {
	var b strings.Builder
	b.WriteString(`<nmaprun><host><status state="up"/><address addr="`)
	xml.EscapeText(&b, []byte(r.IP))
	b.WriteString(`" addrtype="ipv4"/><ports>`)
	for _, p := range r.Ports {
		b.WriteString(`<port protocol="tcp" portid="`)
		b.WriteString(strconv.Itoa(p.Port))
		b.WriteString(`"><state state="open"/>`)
		if p.Service != "" {
			b.WriteString(`<service name="`)
			xml.EscapeText(&b, []byte(p.Service))
			b.WriteString(`"/>`)
		}
		b.WriteString(`</port>`)
	}
	b.WriteString(`</ports></host></nmaprun>`)
	return []byte(b.String())
}

// parsePortSpec turns ndscan's port syntax ("22,80,443" or "1-1024", possibly
// mixed) into an explicit port list. Empty input deliberately returns nil so
// the sweep uses its default set; malformed input must never take that path.
func parsePortSpec(spec string) ([]int, error) {
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return nil, nil
	}
	seen := make(map[int]bool)
	var out []int
	add := func(p int) {
		if p >= 1 && p <= 65535 && !seen[p] {
			seen[p] = true
			out = append(out, p)
		}
	}
	for _, part := range strings.Split(spec, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			return nil, fmt.Errorf("invalid port token %q", part)
		}
		lo, hi, isRange := strings.Cut(part, "-")
		if !isRange {
			p, err := strconv.Atoi(part)
			if err != nil || p < 1 || p > 65535 {
				return nil, fmt.Errorf("invalid port token %q", part)
			}
			add(p)
			continue
		}
		start, err1 := strconv.Atoi(strings.TrimSpace(lo))
		end, err2 := strconv.Atoi(strings.TrimSpace(hi))
		if err1 != nil || err2 != nil || start < 1 || end > 65535 || start > end {
			return nil, fmt.Errorf("invalid port token %q", part)
		}
		for p := start; p <= end; p++ {
			add(p)
		}
	}
	return out, nil
}

func incompleteError(probes int) error {
	if probes == 0 {
		return nil
	}
	return fmt.Errorf("native port scan incomplete: %d probes skipped after file descriptor exhaustion", probes)
}

// NativePortScanViable reports whether a native port scan can serve this
// config. It cannot when the caller needs what only nmap provides: service
// versions, OS detection, or NSE output (the -A presets), or UDP.
func NativePortScanViable(cfg Config, runner Runner) bool {
	if _, local := runner.(LocalRunner); !local {
		return false // probes must originate from this machine
	}
	switch cfg.Preset {
	case "default", "deep", "udp":
		return false // these want nmap's -A / -sU capabilities
	}
	return true
}

// nativeScanBudget is how long a native port scan may run before the caller
// should consider it stalled. Native scans complete in well under a second per
// host on a LAN; this is a backstop, not a working limit.
const nativeScanBudget = 2 * time.Minute
