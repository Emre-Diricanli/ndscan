package ui

import (
	"testing"

	"github.com/Emre-Diricanli/ndscan/internal/scan"
)

func TestIPLess_NumericNotLexical(t *testing.T) {
	cases := []struct {
		a, b string
		want bool
		why  string
	}{
		{"192.168.1.9", "192.168.1.10", true, "9 sorts before 10 numerically"},
		{"192.168.1.10", "192.168.1.9", false, "10 does not sort before 9"},
		{"192.168.1.2", "192.168.1.100", true, "2 before 100"},
		{"10.0.0.1", "9.0.0.1", false, "10.x sorts after 9.x"},
		{"192.168.1.1", "192.168.1.1", false, "equal is not less"},
		// IPv4 and IPv6 both map through To16, so ordering stays total.
		{"::1", "192.168.1.1", true, "ipv6 loopback sorts before v4-mapped"},
		// Unparseable values fall back to string compare rather than panicking.
		{"not-an-ip", "zzz", true, "fallback to string compare"},
	}
	for _, c := range cases {
		if got := IPLess(c.a, c.b); got != c.want {
			t.Errorf("IPLess(%q, %q) = %v, want %v (%s)", c.a, c.b, got, c.want, c.why)
		}
	}
}

// mergePorts must order rows numerically, matching the TUI. Previously it used
// a lexical compare, so a CLI table put .10 before .9 while the TUI did not.
func TestMergePorts_SortsNumerically(t *testing.T) {
	mk := func(ip string) scan.HostResult {
		xml := `<nmaprun><host><status state="up"/>` +
			`<address addr="` + ip + `" addrtype="ipv4"/><ports></ports></host></nmaprun>`
		return scan.HostResult{IP: ip, XMLBytes: []byte(xml)}
	}
	res := []scan.HostResult{
		mk("192.168.1.10"),
		mk("192.168.1.9"),
		mk("192.168.1.100"),
		mk("192.168.1.2"),
	}
	rows := BuildRows(res, nil, false, false, nil)
	got := make([]string, 0, len(rows))
	for _, r := range rows {
		got = append(got, r.IP)
	}
	want := []string{"192.168.1.2", "192.168.1.9", "192.168.1.10", "192.168.1.100"}
	if len(got) != len(want) {
		t.Fatalf("got %d rows (%v), want %d", len(got), got, len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("row order = %v, want %v", got, want)
		}
	}
}
