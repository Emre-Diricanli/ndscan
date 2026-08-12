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
	// NoEarlyAbandon disables the multi-target early-abandon optimisation (see
	// stagedSweep). When a sweep covers several targets and one of them shows
	// zero signs of life in the first probe round, the remaining ports are
	// skipped for that target's addresses: an empty subnet is a far likelier
	// explanation than a subnet where nothing answers any of the first few
	// probe ports, and probing the rest is the bulk of a multi-subnet sweep's
	// wall-clock. The accepted cost is missing a host that answers only on a
	// later port in an otherwise silent subnet. Set this when missing such a
	// host is worse than the wait. A single-target scan is never abandoned —
	// naming one target is an explicit request for a thorough scan.
	NoEarlyAbandon bool
}

// Result is one discovered host.
type Result struct {
	IP string
	// RTT is the duration of the first successful TCP connect used to discover
	// this host, and zero when no connect was needed.
	//
	// On a directly-attached segment most hosts are recovered from the ARP
	// cache without a probe, so a zero here is usually "we did not have to ask"
	// rather than "the host is slow". That is the honest reading: inventing a
	// latency for a host we never dialled would be worse than an empty column.
	RTT time.Duration
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
	// stagingThreshold is how many concurrency-widths of work a sweep must have
	// before staged probing beats probing everything at once, expressed as a
	// multiplier on Concurrency. Below it the whole scan fits in a couple of
	// waves and an extra barrier is pure added latency; above it the probe count
	// dominates and staging cuts it by roughly the port-list length. A /24 with
	// the default settings sits well under; a /16 sits far above.
	stagingThreshold = 4
	// abandonRound1Ports is how wide round 1 is allowed to be when early
	// abandonment is in play. Pronouncing a subnet dead on a single silent port
	// would miss every host that answers only on 80 or 443, so the verdict waits
	// for a few high-yield ports. On a genuinely empty subnet that is two extra
	// probes per address, against the ~13 per address that abandoning round 2
	// then saves.
	abandonRound1Ports = 3
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

	// 2. Staged TCP connect sweep over the remaining space. The per-target
	// grouping travels with the flat list so the sweep can tell which addresses
	// belong to which target — early abandonment is decided per target, and a
	// hit in one subnet must never keep a sibling subnet alive.
	if !cfg.SkipTCP && len(addrs) > 0 {
		for _, hit := range stagedSweep(ctx, addrs, expandTargetGroups(targets), cfg) {
			r := get(hit.ip)
			r.ViaTCP = true
			if r.RTT == 0 {
				r.RTT = hit.rtt
			}
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
		// Derive the default from the descriptor limit rather than assuming a
		// constant is safe everywhere: each in-flight dial holds an fd, and a
		// container or CI runner with a low ulimit would otherwise exhaust the
		// table and silently mis-report open ports as closed.
		cfg.Concurrency = fdConcurrencyBudget()
	}
	if cfg.Concurrency > maxConcurrency {
		cfg.Concurrency = maxConcurrency
	}
	return cfg
}

type hit struct {
	ip   string
	port int
	rtt  time.Duration
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
//
// groups carries the addresses of each requested target, for early
// abandonment: when the sweep covers several targets, a target whose every
// address stays silent through round 1 is abandoned — round 2 is skipped for
// its addresses. Sibling-subnet sweeps generate speculative targets that often
// don't exist, and a dead /24 would otherwise eat the full port list against
// all 254 addresses. The verdict is only ever pronounced on a COMPLETED round 1
// with zero hits — a slow subnet answers eventually and is kept, and a
// cancelled context abandons nothing. Nil or a single group disables
// abandonment entirely.
func stagedSweep(ctx context.Context, addrs []string, groups [][]string, cfg Config) []hit {
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

	// Staging trades a round-trip for a smaller probe count, and that trade is
	// only worth making when the probes don't fit in one concurrent wave.
	//
	// Below the threshold every (address, port) pair is already in flight
	// simultaneously, so the scan costs exactly one timeout and there is nothing
	// to save — adding a barrier just serialises two waves where one would do.
	// Measured on a live /24: staging unconditionally cost ~1.25s against ~930ms
	// for probing everything at once, for identical results. Above the
	// threshold the arithmetic inverts: a /16 is ~1M probes against a few
	// thousand concurrent slots, so probe count, not round-trips, sets the
	// wall-clock and cutting it 16x dominates the one extra barrier.
	pending := addrs
	switch {
	case ctx.Err() != nil || len(cfg.Ports) == 0:
	case len(addrs)*len(cfg.Ports) <= cfg.Concurrency*stagingThreshold:
		pending = s.probe(ctx, pending, cfg.Ports)
	default:
		// Round 1 eliminates most live addresses for the cost of a single port.
		// The remaining ports are NOT a further barrier per port: each costs the
		// full timeout of its slowest member, and sixteen of them floored
		// discovery at 4.94s in testing. The survivors go through the rest
		// concurrently, so the tail costs one timeout rather than fifteen.
		//
		// With several targets in play, round 1 widens from one port to a few:
		// it doubles as the census that decides whether a whole target is
		// abandoned, and a single port is too narrow a jury for that verdict
		// (see abandonRound1Ports).
		abandon := len(groups) > 1 && !cfg.NoEarlyAbandon
		round1 := cfg.Ports[:1]
		if abandon && len(cfg.Ports) > abandonRound1Ports {
			round1 = cfg.Ports[:abandonRound1Ports]
		}
		pending = s.probe(ctx, pending, round1)
		if abandon && ctx.Err() == nil {
			pending = s.dropSilentGroups(pending, groups)
		}
		if len(cfg.Ports) > len(round1) && len(pending) > 0 && ctx.Err() == nil {
			pending = s.probe(ctx, pending, cfg.Ports[len(round1):])
		}
	}

	// Every probe above, answered or not, forced an ARP resolution for its
	// destination on the local segment. The cache is therefore materially warmer
	// than it was at the start of the scan, and re-reading it is free — no
	// packets, microseconds. This is the only way we see a host that ignored
	// every port we tried but did reply at L2.
	//
	// The still-silent set is rebuilt from `answered` rather than taken from
	// pending: early-abandoned addresses are out of pending, but their round-1
	// probes warmed the cache all the same, and dropping them here would take
	// away this safety net exactly where abandonment needs it most.
	if cfg.Attached && cfg.ARP != nil && ctx.Err() == nil {
		s.mu.Lock()
		still := make(map[string]bool, len(addrs))
		for _, ip := range addrs {
			if !s.answered[ip] {
				still[ip] = true
			}
		}
		s.mu.Unlock()
		if len(still) > 0 {
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

// dropSilentGroups filters pending down to the addresses whose target group
// produced at least one round-1 hit. A group with zero hits is abandoned: the
// expected finding there is an empty subnet, and sweeping the remaining ports
// across it is what made a 10-subnet sweep take 6s while only 3 subnets had
// anything on them. Only round 2 is skipped — the group has already been
// probed on round 1's ports, and the post-sweep ARP re-read still covers it.
//
// An address shared by several targets is kept if ANY of its groups showed
// life: overlapping targets must not condemn each other.
func (s *sweepState) dropSilentGroups(pending []string, groups [][]string) []string {
	s.mu.Lock()
	alive := make([]bool, len(groups))
	for i, g := range groups {
		for _, ip := range g {
			if s.answered[ip] {
				alive[i] = true
				break
			}
		}
	}
	s.mu.Unlock()

	keep := make(map[string]bool, len(pending))
	for i, g := range groups {
		if !alive[i] {
			continue
		}
		for _, ip := range g {
			keep[ip] = true
		}
	}
	out := pending[:0]
	for _, ip := range pending {
		if keep[ip] {
			out = append(out, ip)
		}
	}
	return out
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

	started := time.Now()
	conn, err := s.dialer.DialContext(ctx, "tcp", net.JoinHostPort(ip, strconv.Itoa(port)))
	rtt := time.Since(started)
	switch {
	case err == nil:
		conn.Close()
		s.record(hit{ip: ip, port: port, rtt: rtt})
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
	for _, t := range targets {
		for _, s := range expandOne(t) {
			if !seen[s] {
				seen[s] = true
				out = append(out, s)
			}
		}
	}
	return out
}

// expandTargetGroups expands each target separately, preserving which
// addresses belong to which target; early abandonment is decided per group.
// Targets that expand to nothing are dropped so an unparseable or refused
// target can't count as a group of its own.
func expandTargetGroups(targets []string) [][]string {
	var groups [][]string
	for _, t := range targets {
		if g := expandOne(t); len(g) > 0 {
			groups = append(groups, g)
		}
	}
	return groups
}

// expandOne expands a single CIDR or bare address. Nothing is deduplicated
// here — that is the caller's job when several targets are combined.
func expandOne(t string) []string {
	if a, err := netip.ParseAddr(t); err == nil {
		return []string{a.String()}
	}
	p, err := netip.ParsePrefix(t)
	if err != nil || !p.Addr().Is4() {
		return nil
	}
	p = p.Masked()
	if p.Bits() < 16 {
		return nil // too broad to expand; caller should narrow it
	}
	if p.Bits() == 32 {
		return []string{p.Addr().String()}
	}
	// Walk the prefix, skipping network and broadcast addresses.
	var out []string
	first := p.Addr().Next()
	for a := first; p.Contains(a); a = a.Next() {
		next := a.Next()
		if !p.Contains(next) {
			break // a is the broadcast address
		}
		out = append(out, a.String())
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
