package netinfo

import (
	"strings"
	"testing"
)

func contains(s []string, want string) bool {
	for _, v := range s {
		if v == want {
			return true
		}
	}
	return false
}

func TestSiblingCandidates_DerivesCommonSiblings(t *testing.T) {
	locals := []Network{{Interface: "en0", CIDR: "192.168.2.0/24", Addr: "192.168.2.157"}}
	got := SiblingCandidates(locals, nil)

	// The .100 VLAN is the whole point — it must be proposed.
	if !contains(got, "192.168.100.0/24") {
		t.Errorf("expected 192.168.100.0/24 among candidates, got %v", got)
	}
	// A couple other common ones.
	for _, want := range []string{"192.168.1.0/24", "192.168.10.0/24"} {
		if !contains(got, want) {
			t.Errorf("expected %s among candidates, got %v", want, got)
		}
	}
	// The machine's own network must never be offered.
	if contains(got, "192.168.2.0/24") {
		t.Errorf("own network 192.168.2.0/24 must not be a candidate: %v", got)
	}
}

func TestSiblingCandidates_ExplicitAlwaysIncluded(t *testing.T) {
	locals := []Network{{Interface: "en0", CIDR: "10.0.5.0/24", Addr: "10.0.5.9"}}
	// An explicit subnet outside the common set and outside the local /16.
	got := SiblingCandidates(locals, []string{"172.16.30.0/24"})
	if !contains(got, "172.16.30.0/24") {
		t.Errorf("explicit 172.16.30.0/24 must be included: %v", got)
	}
}

func TestSiblingCandidates_AcceptsPartialAndBareForms(t *testing.T) {
	got := SiblingCandidates(nil, []string{"192.168.100", "10.20.30.44"})
	if !contains(got, "192.168.100.0/24") {
		t.Errorf("partial '192.168.100' should become /24: %v", got)
	}
	// A bare host address collapses to its /24.
	if !contains(got, "10.20.30.0/24") {
		t.Errorf("bare host '10.20.30.44' should collapse to /24: %v", got)
	}
}

func TestSiblingCandidates_NeverReturnsAttached(t *testing.T) {
	locals := []Network{
		{Interface: "en0", CIDR: "192.168.2.0/24", Addr: "192.168.2.157"},
		{Interface: "en1", CIDR: "192.168.1.0/24", Addr: "192.168.1.5"},
	}
	// Even though .1 is in the common set, we're attached to it — exclude it.
	got := SiblingCandidates(locals, []string{"192.168.1.0/24"})
	if contains(got, "192.168.1.0/24") {
		t.Errorf("attached 192.168.1.0/24 must be excluded even if named: %v", got)
	}
	if contains(got, "192.168.2.0/24") {
		t.Errorf("attached 192.168.2.0/24 must be excluded: %v", got)
	}
}

func TestSiblingCandidates_Deduplicates(t *testing.T) {
	locals := []Network{{Interface: "en0", CIDR: "192.168.2.0/24", Addr: "192.168.2.157"}}
	// 100 is both in the common set and named explicitly — must appear once.
	got := SiblingCandidates(locals, []string{"192.168.100.0/24", "192.168.100.5"})
	n := 0
	for _, v := range got {
		if v == "192.168.100.0/24" {
			n++
		}
	}
	if n != 1 {
		t.Errorf("192.168.100.0/24 appears %d times, want 1: %v", n, got)
	}
}

func TestSiblingCandidates_Bounded(t *testing.T) {
	locals := []Network{{Interface: "en0", CIDR: "192.168.2.0/24", Addr: "192.168.2.157"}}
	got := SiblingCandidates(locals, nil)
	// Deliberately bounded: nowhere near all 255 possible siblings.
	if len(got) > 16 {
		t.Errorf("candidate set should be bounded, got %d: %v", len(got), got)
	}
	// Every entry must be a valid /24 CIDR.
	for _, c := range got {
		if !strings.HasSuffix(c, "/24") {
			t.Errorf("candidate %q is not a /24", c)
		}
	}
}

func TestSiblingCandidates_IgnoresNonV4AndGarbage(t *testing.T) {
	locals := []Network{{Interface: "utun8", CIDR: "100.127.245.23/32", Addr: "100.127.245.23"}}
	// /32 yields no /24 siblings; garbage explicit entries are dropped.
	got := SiblingCandidates(locals, []string{"", "not-an-ip", "999.1.1.1"})
	for _, c := range got {
		if c == "" || strings.Contains(c, "not-an-ip") {
			t.Errorf("garbage leaked into candidates: %v", got)
		}
	}
}
