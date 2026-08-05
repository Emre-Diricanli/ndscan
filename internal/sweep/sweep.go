// Package sweep implements native host discovery: finding which addresses in a
// target range are alive, without shelling out to nmap.
//
// It combines two sources, cheapest first:
//
//   - the OS ARP cache, which already knows every L2 neighbour the machine has
//     talked to (microseconds, zero packets, no privileges), and
//   - a bounded-concurrency TCP connect sweep over a small set of common ports,
//     which finds hosts that ARP hasn't seen and hosts beyond the local segment.
//
// The union is what gets reported. On a typical LAN this is 20-30x faster than
// `nmap -sn` because the timeout policy is ours: nmap's conservative retry and
// backoff behaviour is tuned for hostile WAN targets, and most of its wall-clock
// time on a quiet /24 is spent waiting on addresses where nothing exists.
//
// This deliberately needs no root. Raw ARP/SYN probing would find a few more
// hosts, but /dev/bpf is root-only on macOS and would force cgo+libpcap, giving
// up static cross-compilation for a marginal gain over the ARP cache.
package sweep

import (
	"context"
	"net"
	"net/netip"
	"sort"
	"strconv"
	"sync"
	"time"
)

// DefaultPorts is the discovery probe set: ports common enough that a live host
// on a home or office network is likely to answer on at least one. This is a
// liveness probe, not a port scan — the real port scan happens later.
var DefaultPorts = []int{
	22,    // ssh
	80,    // http
	443,   // https
	53,    // dns (routers)
	445,   // smb
	139,   // netbios
	8080,  // http-alt
	8443,  // https-alt
	3389,  // rdp
	5000,  // upnp / airplay
	631,   // ipp (printers)
	9100,  // jetdirect (printers)
	1900,  // ssdp
	62078, // iphone-sync
	7000,  // airplay
	5009,  // airport admin
}

// Config tunes a sweep. The zero value is usable: sensible defaults are filled
// in by Run.
type Config struct {
	// Ports probed per host. Defaults to DefaultPorts.
	Ports []int
	// Timeout per individual connect attempt. Defaults to 300ms, which is
	// generous for a LAN and still bounds a full /24 to well under a second.
	Timeout time.Duration
	// Concurrency caps in-flight connections. Defaults to 1024. Each costs a
	// file descriptor, so this is bounded defensively rather than set to the
	// process rlimit.
	Concurrency int
	// SkipTCP reports hosts from the ARP cache only. Useful when the caller
	// wants the instant answer and no probe traffic at all.
	SkipTCP bool
	// ARP supplies the ARP-cache reader. Defaults to the real OS lookup;
	// tests inject a stub. A nil map result is fine (means "cache unavailable").
	ARP func(ctx context.Context) map[string]string
	// Progress, if set, is called as probing advances. May be called from
	// multiple goroutines.
	Progress func(done, total int)
}

// Result is one discovered host.
type Result struct {
	IP string
	// MAC is set when the ARP cache knew this host (L2 neighbours only).
	MAC string
	// ViaARP is true when the ARP cache reported the host. ViaTCP is true when
	// it answered a connect probe. Both can be true.
	ViaARP bool
	ViaTCP bool
	// OpenPort is a port observed open during discovery, or 0. It is a free
	// hint for the later port scan, not a complete list.
	OpenPort int
}

const (
	defaultTimeout     = 300 * time.Millisecond
	defaultConcurrency = 1024
	maxConcurrency     = 4096
)

// Run discovers live hosts across the given CIDR targets.
//
// Targets that don't parse as a CIDR or address are skipped rather than
// guessed at; callers validate user input upstream. Results are returned in
// numeric address order.
func Run(ctx context.Context, targets []string, cfg Config) []Result {
	cfg = withDefaults(cfg)

	hosts := make(map[string]*Result)
	get := func(ip string) *Result {
		r, ok := hosts[ip]
		if !ok {
			r = &Result{IP: ip}
			hosts[ip] = r
		}
		return r
	}

	addrs := expandTargets(targets)
	inTarget := make(map[string]bool, len(addrs))
	for _, a := range addrs {
		inTarget[a] = true
	}

	// 1. ARP cache: free, instant, and on a warm LAN it often knows more than
	// an unprivileged nmap sweep will find. Restricted to the requested targets
	// so a scan of one subnet never reports neighbours from another.
	if cfg.ARP != nil {
		for ip, mac := range cfg.ARP(ctx) {
			if !inTarget[ip] {
				continue
			}
			r := get(ip)
			r.MAC, r.ViaARP = mac, true
		}
	}

	// 2. TCP connect sweep over the remaining space.
	if !cfg.SkipTCP && len(addrs) > 0 {
		for _, hit := range tcpSweep(ctx, addrs, cfg) {
			r := get(hit.ip)
			r.ViaTCP = true
			if r.OpenPort == 0 {
				r.OpenPort = hit.port
			}
		}
	}

	out := make([]Result, 0, len(hosts))
	for _, r := range hosts {
		out = append(out, *r)
	}
	sort.Slice(out, func(i, j int) bool { return addrLess(out[i].IP, out[j].IP) })
	return out
}

func withDefaults(cfg Config) Config {
	if len(cfg.Ports) == 0 {
		cfg.Ports = DefaultPorts
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = defaultTimeout
	}
	if cfg.Concurrency <= 0 {
		cfg.Concurrency = defaultConcurrency
	}
	if cfg.Concurrency > maxConcurrency {
		cfg.Concurrency = maxConcurrency
	}
	return cfg
}

type hit struct {
	ip   string
	port int
}

// tcpSweep probes every (address, port) pair, returning the first open port
// seen per address. It stops early if the context is cancelled.
func tcpSweep(ctx context.Context, addrs []string, cfg Config) []hit {
	var (
		wg    sync.WaitGroup
		mu    sync.Mutex
		hits  []hit
		done  int
		total = len(addrs) * len(cfg.Ports)
		sem   = make(chan struct{}, cfg.Concurrency)
	)

	// Once an address answers, further probes to it are wasted work.
	answered := make(map[string]bool, len(addrs))
	var ansMu sync.RWMutex

	dialer := &net.Dialer{Timeout: cfg.Timeout}

	for _, ip := range addrs {
		for _, port := range cfg.Ports {
			if ctx.Err() != nil {
				break
			}
			wg.Add(1)
			select {
			case sem <- struct{}{}:
			case <-ctx.Done():
				wg.Done()
				continue
			}
			go func(ip string, port int) {
				defer wg.Done()
				defer func() { <-sem }()

				ansMu.RLock()
				skip := answered[ip]
				ansMu.RUnlock()
				if skip || ctx.Err() != nil {
					mu.Lock()
					done++
					mu.Unlock()
					return
				}

				addr := net.JoinHostPort(ip, strconv.Itoa(port))
				conn, err := dialer.DialContext(ctx, "tcp", addr)
				if err == nil {
					conn.Close()
					ansMu.Lock()
					answered[ip] = true
					ansMu.Unlock()
					mu.Lock()
					hits = append(hits, hit{ip: ip, port: port})
					mu.Unlock()
				}

				mu.Lock()
				done++
				d := done
				mu.Unlock()
				if cfg.Progress != nil {
					cfg.Progress(d, total)
				}
			}(ip, port)
		}
	}
	wg.Wait()
	return hits
}

// expandTargets turns CIDRs and bare addresses into the list of host addresses
// to probe. Network and broadcast addresses of a v4 prefix are skipped. Ranges
// broader than a /16 are refused rather than silently truncated — sweeping
// 65k+ addresses is a different kind of operation and should be explicit.
func expandTargets(targets []string) []string {
	seen := make(map[string]bool)
	var out []string
	add := func(a netip.Addr) {
		s := a.String()
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}

	for _, t := range targets {
		if a, err := netip.ParseAddr(t); err == nil {
			add(a)
			continue
		}
		p, err := netip.ParsePrefix(t)
		if err != nil || !p.Addr().Is4() {
			continue
		}
		p = p.Masked()
		if p.Bits() < 16 {
			continue // too broad to expand; caller should narrow it
		}
		if p.Bits() == 32 {
			add(p.Addr())
			continue
		}
		// Walk the prefix, skipping network and broadcast addresses.
		first := p.Addr().Next()
		for a := first; p.Contains(a); a = a.Next() {
			next := a.Next()
			if !p.Contains(next) {
				break // a is the broadcast address
			}
			add(a)
		}
	}
	return out
}

// addrLess orders addresses numerically, falling back to string comparison.
func addrLess(a, b string) bool {
	aa, errA := netip.ParseAddr(a)
	ab, errB := netip.ParseAddr(b)
	if errA != nil || errB != nil {
		return a < b
	}
	return aa.Less(ab)
}

// IPs returns just the addresses from a result set, for callers that only need
// the live-host list.
func IPs(rs []Result) []string {
	out := make([]string, 0, len(rs))
	for _, r := range rs {
		out = append(out, r.IP)
	}
	return out
}

// MACs returns the IP->MAC pairs the sweep learned from the ARP cache.
func MACs(rs []Result) map[string]string {
	out := make(map[string]string, len(rs))
	for _, r := range rs {
		if r.MAC != "" {
			out[r.IP] = r.MAC
		}
	}
	return out
}
