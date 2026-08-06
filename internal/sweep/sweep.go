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
	"errors"
	"net"
	"net/netip"
	"sort"
	"strconv"
	"sync"
	"syscall"
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
	// Attached marks the targets as being on a directly-connected segment,
	// which unlocks two shortcuts that are only sound at L2 (see stagedSweep):
	// treating a TCP refusal as proof of liveness, and re-reading the ARP cache
	// after probing. Off by default — the conservative reading is that we don't
	// know what's between us and the target.
	Attached bool
	// OnResult, if set, is called with each host as it is discovered rather than
	// only at the end. Called from multiple goroutines.
	OnResult func(Result)
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
	// Refused is true when the host was found only because it actively reset a
	// connection. It is alive, but nothing in the probe set was listening — so
	// an empty port list for this host is a real finding, not a missed scan.
	Refused bool
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

	// ARP hits are known before a single packet is sent, so stream them first.
	if cfg.OnResult != nil {
		for _, r := range hosts {
			cfg.OnResult(*r)
		}
	}

	// 2. Staged TCP connect sweep over the remaining space.
	if !cfg.SkipTCP && len(addrs) > 0 {
		for _, hit := range stagedSweep(ctx, addrs, cfg) {
			r := get(hit.ip)
			r.ViaTCP = true
			if r.OpenPort == 0 {
				r.OpenPort = hit.port
			}
			// A refusal proves the host exists but tells us nothing about which
			// ports are open, so it must not be recorded as an open-port hint.
			if hit.refused {
				r.Refused = true
			}
			if cfg.OnResult != nil && !r.ViaARP {
				cfg.OnResult(*r) // ARP hosts already streamed above
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
	// refused is true when the address answered with a TCP reset rather than an
	// accepted connection. Something is there; no port is open.
	refused bool
}

// stagedSweep probes addresses in rounds instead of scheduling every
// (address, port) pair upfront.
//
// The old approach queued len(addrs)*len(Ports) probes — on a /16 that is about
// a million connect attempts, and no amount of concurrency tuning makes a
// million timeouts fast. Almost all of that work is wasted: the overwhelming
// majority of addresses in a real network are empty, and the ones that aren't
// usually answer on the first port tried.
//
// So: probe one high-yield port across every address first. Addresses that
// answer are done. Only the still-silent remainder pays for the rest of the port
// list. On a quiet network this collapses the probe count from
// addresses x ports to roughly one per address.
func stagedSweep(ctx context.Context, addrs []string, cfg Config) []hit {
	s := &sweepState{
		cfg:      cfg,
		answered: make(map[string]bool, len(addrs)),
		dialer:   &net.Dialer{Timeout: cfg.Timeout},
		// The denominator is the worst case (every address staying silent
		// through every port). Progress therefore only ever runs ahead of
		// schedule, which is the honest direction for a bar to be wrong in — it
		// never stalls at 99% waiting for work that was already skipped.
		total: len(addrs) * len(cfg.Ports),
	}

	// Round 1 is a barrier, and it is the one that pays for itself: for the cost
	// of a single port it eliminates most live addresses from every later probe.
	//
	// The remaining ports are deliberately NOT run as further barriers. Each
	// barrier costs the full timeout of its slowest member, so sixteen sequential
	// rounds would floor discovery at 16 x timeout — measured at 4.94s on a /24
	// that finishes in ~1.2s otherwise, i.e. four times *worse* than probing
	// everything at once. So the survivors go through the remaining ports
	// concurrently, and the tail costs one timeout rather than fifteen.
	pending := addrs
	if len(cfg.Ports) > 0 && ctx.Err() == nil {
		pending = s.probe(ctx, pending, cfg.Ports[:1])
		if len(cfg.Ports) > 1 && len(pending) > 0 && ctx.Err() == nil {
			pending = s.probe(ctx, pending, cfg.Ports[1:])
		}
	}

	// Every probe above, answered or not, forced an ARP resolution for its
	// destination on the local segment. The cache is therefore materially warmer
	// than it was at the start of the scan, and re-reading it is free — no
	// packets, microseconds. This is the only way we see a host that ignored
	// every port we tried but did reply at L2.
	if cfg.Attached && cfg.ARP != nil && ctx.Err() == nil && len(pending) > 0 {
		still := make(map[string]bool, len(pending))
		for _, ip := range pending {
			still[ip] = true
		}
		for ip := range cfg.ARP(ctx) {
			if !still[ip] {
				continue
			}
			s.mu.Lock()
			if !s.answered[ip] {
				s.answered[ip] = true
				s.hits = append(s.hits, hit{ip: ip})
			}
			s.mu.Unlock()
		}
	}

	// Progress is reported against a worst-case denominator, so a scan that
	// short-circuited early would otherwise leave the bar short of full.
	if cfg.Progress != nil && ctx.Err() == nil {
		cfg.Progress(s.total, s.total)
	}
	return s.hits
}

// sweepState is the shared bookkeeping for one staged sweep.
type sweepState struct {
	cfg      Config
	dialer   *net.Dialer
	total    int
	mu       sync.Mutex
	hits     []hit
	done     int
	answered map[string]bool
}

// probe dials every (address, port) pair concurrently and returns the addresses
// that never answered. Probes against an address that has already answered are
// skipped, so passing the full port list here still costs only one round-trip
// per live host.
func (s *sweepState) probe(ctx context.Context, addrs []string, ports []int) []string {
	var (
		wg  sync.WaitGroup
		sem = make(chan struct{}, s.cfg.Concurrency)
	)
	for _, ip := range addrs {
		for _, port := range ports {
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
				s.dial(ctx, ip, port)
			}(ip, port)
		}
	}
	wg.Wait()

	s.mu.Lock()
	defer s.mu.Unlock()
	remaining := make([]string, 0, len(addrs))
	for _, ip := range addrs {
		if !s.answered[ip] {
			remaining = append(remaining, ip)
		}
	}
	return remaining
}

// dial performs one probe and records what it proved.
func (s *sweepState) dial(ctx context.Context, ip string, port int) {
	s.mu.Lock()
	skip := s.answered[ip]
	s.mu.Unlock()
	if skip || ctx.Err() != nil {
		s.advance()
		return
	}

	conn, err := s.dialer.DialContext(ctx, "tcp", net.JoinHostPort(ip, strconv.Itoa(port)))
	switch {
	case err == nil:
		conn.Close()
		s.record(hit{ip: ip, port: port})
	case s.cfg.Attached && isRefused(err):
		// A reset means a TCP stack replied. On a directly-attached segment that
		// stack belongs to the host itself, so this is solid proof of liveness
		// even though nothing is listening — and it catches hosts that would
		// otherwise be invisible for having no open port in our probe set.
		//
		// Off-segment we can't claim that: the reset may equally have come from a
		// firewall answering on behalf of an address where nothing exists. Hence
		// the Attached gate.
		s.record(hit{ip: ip, refused: true})
	}
	s.advance()
}

// record marks an address alive, keeping only the first proof per address.
func (s *sweepState) record(h hit) {
	s.mu.Lock()
	if !s.answered[h.ip] {
		s.answered[h.ip] = true
		s.hits = append(s.hits, h)
	}
	s.mu.Unlock()
}

func (s *sweepState) advance() {
	s.mu.Lock()
	s.done++
	d := s.done
	s.mu.Unlock()
	if s.cfg.Progress != nil {
		s.cfg.Progress(d, s.total)
	}
}

// isRefused reports whether a dial failed because the target actively refused
// the connection, as opposed to timing out or being unreachable. Only a refusal
// proves a TCP stack is listening at that address.
func isRefused(err error) bool {
	return errors.Is(err, syscall.ECONNREFUSED)
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
