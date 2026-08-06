package sweep

import (
	"errors"
	"fmt"
	"net"
	"syscall"
	"testing"
)

func TestConcurrencyBudgetForLimit(t *testing.T) {
	tests := []struct {
		name string
		soft uint64
		want int
	}{
		{name: "tiny limit uses floor", soft: 16, want: minFDConcurrency},
		{name: "ordinary limit reserves headroom", soft: 1024, want: 256},
		{name: "large limit respects scanner ceiling", soft: 1 << 20, want: maxConcurrency},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := concurrencyBudgetForLimit(tt.soft); got != tt.want {
				t.Fatalf("concurrencyBudgetForLimit(%d) = %d, want %d", tt.soft, got, tt.want)
			}
		})
	}
}

func TestFDConcurrencyBudgetIsBounded(t *testing.T) {
	got := fdConcurrencyBudget()
	if got < minFDConcurrency || got > maxConcurrency {
		t.Fatalf("fdConcurrencyBudget() = %d, want [%d, %d]", got, minFDConcurrency, maxConcurrency)
	}
}

func TestIsResourceExhausted(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{name: "nil", err: nil},
		{name: "emfile", err: syscall.EMFILE, want: true},
		{name: "wrapped enfile", err: fmt.Errorf("dial failed: %w", syscall.ENFILE), want: true},
		{name: "net operation wraps errno", err: &net.OpError{Op: "dial", Net: "tcp", Err: syscall.EMFILE}, want: true},
		{name: "text fallback", err: errors.New("socket: Too Many Open Files"), want: true},
		{name: "connection refused", err: syscall.ECONNREFUSED},
		{name: "timeout", err: contextDeadlineExceeded{}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isResourceExhausted(tt.err); got != tt.want {
				t.Fatalf("isResourceExhausted(%v) = %v, want %v", tt.err, got, tt.want)
			}
		})
	}
}

type contextDeadlineExceeded struct{}

func (contextDeadlineExceeded) Error() string   { return "context deadline exceeded" }
func (contextDeadlineExceeded) Timeout() bool   { return true }
func (contextDeadlineExceeded) Temporary() bool { return true }
