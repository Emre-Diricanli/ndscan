// Package enrich adds best-effort metadata to native scan results.
package enrich

import (
	"context"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"
)

const (
	defaultWorkers        = 16
	defaultLookupTimeout  = 300 * time.Millisecond
	defaultOverallTimeout = 2 * time.Second
)

// Resolver is the subset of net.Resolver used for reverse-DNS enrichment.
// Keeping this boundary narrow makes DNS failure and timing behavior testable
// without depending on the machine's resolver configuration.
type Resolver interface {
	LookupAddr(ctx context.Context, addr string) ([]string, error)
}

// Config bounds reverse-DNS work. The zero value uses a small worker pool,
// 300ms per lookup, a two-second overall deadline, and net.DefaultResolver.
type Config struct {
	Resolver       Resolver
	Workers        int
	LookupTimeout  time.Duration
	OverallTimeout time.Duration
}

// LookupPTR resolves useful PTR names for IPs and returns any names found
// before ctx is cancelled or the overall deadline expires. Missing records and
// individual timeouts are expected enrichment misses, not scan failures.
func LookupPTR(ctx context.Context, ips []string, cfg Config) map[string]string {
	cfg = withDefaults(cfg)
	ctx, cancel := context.WithTimeout(ctx, cfg.OverallTimeout)
	defer cancel()

	results := make(map[string]string)
	jobs := make(chan string)
	var mu sync.Mutex
	var workers sync.WaitGroup

	workers.Add(cfg.Workers)
	for range cfg.Workers {
		go func() {
			defer workers.Done()
			for ip := range jobs {
				lookupCtx, lookupCancel := context.WithTimeout(ctx, cfg.LookupTimeout)
				names, err := cfg.Resolver.LookupAddr(lookupCtx, ip)
				lookupCancel()
				if err != nil {
					continue
				}
				if name := firstUsefulName(ip, names); name != "" {
					mu.Lock()
					results[ip] = name
					mu.Unlock()
				}
			}
		}()
	}

send:
	for _, ip := range ips {
		select {
		case jobs <- ip:
		case <-ctx.Done():
			break send
		}
	}
	close(jobs)
	workers.Wait()
	return results
}

func withDefaults(cfg Config) Config {
	if cfg.Resolver == nil {
		cfg.Resolver = net.DefaultResolver
	}
	if cfg.Workers <= 0 {
		cfg.Workers = defaultWorkers
	}
	if cfg.LookupTimeout <= 0 {
		cfg.LookupTimeout = defaultLookupTimeout
	}
	if cfg.OverallTimeout <= 0 {
		cfg.OverallTimeout = defaultOverallTimeout
	}
	return cfg
}

func firstUsefulName(ip string, names []string) string {
	for _, name := range names {
		name = strings.TrimSuffix(strings.TrimSpace(name), ".")
		if name != "" && !sameAddress(name, ip) {
			return name
		}
	}
	return ""
}

func sameAddress(a, b string) bool {
	aa, errA := netip.ParseAddr(a)
	bb, errB := netip.ParseAddr(b)
	if errA == nil && errB == nil {
		return aa == bb
	}
	return strings.EqualFold(a, b)
}
