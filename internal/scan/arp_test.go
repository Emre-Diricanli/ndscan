package scan

import (
	"context"
	"testing"
)

func TestNormalizeMAC(t *testing.T) {
	cases := map[string]string{
		"f0:9:d:cd:a7:1":    "f0:09:0d:cd:a7:01",
		"B0:6A:41:9E:2E:32": "b0:6a:41:9e:2e:32",
		"1:0:5e:0:0:fb":     "01:00:5e:00:00:fb",
		"bad":               "",
		"00:11:22:33:44":    "", // 5 octets
	}
	for in, want := range cases {
		if got := normalizeMAC(in); got != want {
			t.Errorf("normalizeMAC(%q)=%q want %q", in, got, want)
		}
	}
}

func TestMergeARPHosts(t *testing.T) {
	live := []string{"192.168.86.1"}
	arp := map[string]string{
		"192.168.86.1":  "b0:6a:41:9e:2e:32", // already live
		"192.168.86.44": "f0:09:0d:cd:a7:01", // in subnet, should add
		"10.0.0.5":      "aa:bb:cc:dd:ee:ff", // out of subnet, skip
	}
	got := MergeARPHosts(live, []string{"192.168.86.0/24"}, arp)
	if len(got) != 2 {
		t.Fatalf("want 2 hosts, got %v", got)
	}
	has := map[string]bool{}
	for _, ip := range got {
		has[ip] = true
	}
	if !has["192.168.86.1"] || !has["192.168.86.44"] || has["10.0.0.5"] {
		t.Fatalf("merge wrong: %v", got)
	}
	// hostname target -> no synthetic hosts
	if g := MergeARPHosts(live, []string{"router.local"}, arp); len(g) != 1 {
		t.Fatalf("hostname target should not add hosts: %v", g)
	}
}

func TestARPCacheLive(t *testing.T) {
	if testing.Short() {
		t.Skip()
	}
	m := ARPCache(context.Background(), LocalRunner{})
	t.Logf("ARP cache: %d resolved neighbor(s)", len(m))
	for ip, mac := range m {
		if len(mac) != 17 {
			t.Errorf("mac %q for %s not normalized to 17 chars", mac, ip)
		}
	}
}
