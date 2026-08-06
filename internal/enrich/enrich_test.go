package enrich

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

type resolverFunc func(context.Context, string) ([]string, error)

func (f resolverFunc) LookupAddr(ctx context.Context, addr string) ([]string, error) {
	return f(ctx, addr)
}

func TestLookupPTR(t *testing.T) {
	tests := []struct {
		name    string
		ips     []string
		answers map[string][]string
		errors  map[string]error
		want    map[string]string
	}{
		{
			name: "normalizes names and keeps first useful answer",
			ips:  []string{"192.0.2.1", "192.0.2.2"},
			answers: map[string][]string{
				"192.0.2.1": {"router.example.test."},
				"192.0.2.2": {"192.0.2.2.", "printer.example.test."},
			},
			want: map[string]string{"192.0.2.1": "router.example.test", "192.0.2.2": "printer.example.test"},
		},
		{
			name:    "skips errors empty records and echoed addresses",
			ips:     []string{"192.0.2.3", "192.0.2.4", "2001:db8::1"},
			answers: map[string][]string{"192.0.2.4": {}, "2001:db8::1": {"2001:0db8:0:0:0:0:0:1."}},
			errors:  map[string]error{"192.0.2.3": errors.New("not found")},
			want:    map[string]string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resolver := resolverFunc(func(_ context.Context, ip string) ([]string, error) {
				return tt.answers[ip], tt.errors[ip]
			})
			got := LookupPTR(context.Background(), tt.ips, Config{Resolver: resolver, Workers: 2})
			assertMap(t, got, tt.want)
		})
	}
}

func TestLookupPTRBoundsConcurrency(t *testing.T) {
	const workerCount = 3
	var mu sync.Mutex
	active, peak := 0, 0
	release := make(chan struct{})
	resolver := resolverFunc(func(ctx context.Context, ip string) ([]string, error) {
		mu.Lock()
		active++
		if active > peak {
			peak = active
		}
		mu.Unlock()
		select {
		case <-release:
		case <-ctx.Done():
		}
		mu.Lock()
		active--
		mu.Unlock()
		return nil, ctx.Err()
	})

	done := make(chan struct{})
	go func() {
		LookupPTR(context.Background(), []string{"1", "2", "3", "4", "5", "6"}, Config{
			Resolver: resolver, Workers: workerCount, LookupTimeout: time.Second, OverallTimeout: time.Second,
		})
		close(done)
	}()

	deadline := time.After(time.Second)
	for {
		mu.Lock()
		got := peak
		mu.Unlock()
		if got == workerCount {
			break
		}
		select {
		case <-deadline:
			t.Fatal("workers did not reach configured concurrency")
		case <-time.After(time.Millisecond):
		}
	}
	close(release)
	<-done
	if peak != workerCount {
		t.Fatalf("peak concurrency = %d, want %d", peak, workerCount)
	}
}

func TestLookupPTRReturnsPartialResultsOnDeadline(t *testing.T) {
	resolver := resolverFunc(func(ctx context.Context, ip string) ([]string, error) {
		if ip == "192.0.2.1" {
			return []string{"fast.example.test."}, nil
		}
		<-ctx.Done()
		return nil, ctx.Err()
	})

	start := time.Now()
	got := LookupPTR(context.Background(), []string{"192.0.2.1", "192.0.2.2"}, Config{
		Resolver: resolver, Workers: 1, LookupTimeout: time.Second, OverallTimeout: 30 * time.Millisecond,
	})
	if elapsed := time.Since(start); elapsed > 300*time.Millisecond {
		t.Fatalf("overall timeout returned after %v", elapsed)
	}
	assertMap(t, got, map[string]string{"192.0.2.1": "fast.example.test"})
}

func TestLookupPTRRespectsCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	resolver := resolverFunc(func(ctx context.Context, _ string) ([]string, error) {
		cancel()
		<-ctx.Done()
		return nil, ctx.Err()
	})

	start := time.Now()
	got := LookupPTR(ctx, []string{"192.0.2.1", "192.0.2.2"}, Config{
		Resolver: resolver, Workers: 1, LookupTimeout: time.Second, OverallTimeout: time.Second,
	})
	if elapsed := time.Since(start); elapsed > 300*time.Millisecond {
		t.Fatalf("cancellation returned after %v", elapsed)
	}
	if len(got) != 0 {
		t.Fatalf("got %v after cancellation, want no results", got)
	}
}

func assertMap(t *testing.T, got, want map[string]string) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for ip, name := range want {
		if got[ip] != name {
			t.Fatalf("got[%q] = %q, want %q", ip, got[ip], name)
		}
	}
}
