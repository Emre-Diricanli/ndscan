package enrich

import (
	"context"
	"testing"
	"time"
)

// A scan must never be held up by discovery that nobody answers. Both lookups
// run on every scan, so a silent network is the common case, not the edge one.
func TestLookupsRespectTheirBudget(t *testing.T) {
	budget := 300 * time.Millisecond
	for _, tc := range []struct {
		name string
		run  func(context.Context) map[string]string
	}{
		{"mdns", func(ctx context.Context) map[string]string {
			return LookupMDNS(ctx, MDNSConfig{Timeout: budget})
		}},
		{"ssdp", func(ctx context.Context) map[string]string {
			return LookupSSDP(ctx, SSDPConfig{Timeout: budget})
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			start := time.Now()
			got := tc.run(context.Background())
			elapsed := time.Since(start)
			if elapsed > budget*4 {
				t.Errorf("took %v on a silent network, budget was %v", elapsed, budget)
			}
			if got == nil {
				t.Error("must return an empty map, never nil: callers index it directly")
			}
		})
	}
}

// Cancelling must stop the listener promptly, not run out the clock.
func TestLookupsHonourCancellation(t *testing.T) {
	for _, tc := range []struct {
		name string
		run  func(context.Context) map[string]string
	}{
		{"mdns", func(ctx context.Context) map[string]string {
			return LookupMDNS(ctx, MDNSConfig{Timeout: 10 * time.Second})
		}},
		{"ssdp", func(ctx context.Context) map[string]string {
			return LookupSSDP(ctx, SSDPConfig{Timeout: 10 * time.Second})
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			start := time.Now()
			tc.run(ctx)
			if elapsed := time.Since(start); elapsed > 2*time.Second {
				t.Errorf("cancelled lookup took %v; it should abandon promptly", elapsed)
			}
		})
	}
}
