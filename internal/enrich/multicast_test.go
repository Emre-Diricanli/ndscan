package enrich

import (
	"context"
	"testing"
	"time"
)

func TestLookupMulticastOverlapsPassesAndPrefersMDNS(t *testing.T) {
	started := make(chan string, 2)
	release := make(chan struct{})
	lookup := func(kind, name string) func(context.Context) map[string]string {
		return func(context.Context) map[string]string {
			started <- kind
			<-release
			return map[string]string{"192.0.2.1": name}
		}
	}

	done := make(chan map[string]string, 1)
	go func() {
		done <- lookupMulticast(context.Background(),
			lookup("mdns", "Living-Room-TV"), lookup("ssdp", "UPnP device"))
	}()

	seen := map[string]bool{}
	for range 2 {
		select {
		case kind := <-started:
			seen[kind] = true
		case <-time.After(time.Second):
			t.Fatal("lookups did not overlap")
		}
	}
	close(release)
	got := <-done
	if !seen["mdns"] || !seen["ssdp"] {
		t.Fatalf("started lookups = %v", seen)
	}
	if got["192.0.2.1"] != "Living-Room-TV" {
		t.Fatalf("conflicting name = %q, want mDNS name", got["192.0.2.1"])
	}
}
