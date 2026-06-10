package scan

import "testing"

func TestEffectiveConcurrency(t *testing.T) {
	cases := []struct {
		requested, hosts, want int
	}{
		{64, 3, 3},      // never more workers than hosts
		{64, 200, 64},   // honor the requested cap on big ranges
		{1, 50, 1},      // user can throttle low
		{0, 10, 1},      // clamp non-positive to at least 1
		{32, 0, 1},      // no hosts -> 1 (caller guards len==0 anyway)
		{100, 100, 100}, // equal
	}
	for _, c := range cases {
		if got := effectiveConcurrency(c.requested, c.hosts); got != c.want {
			t.Errorf("effectiveConcurrency(%d,%d) = %d, want %d", c.requested, c.hosts, got, c.want)
		}
	}
}

func TestHostsUpResults(t *testing.T) {
	ips := []string{"192.168.1.10", "192.168.1.20"}
	res := HostsUpResults(ips)
	if len(res) != 2 {
		t.Fatalf("want 2 results, got %d", len(res))
	}
	// each must parse as an up host with the right IP and no open ports
	for i, r := range res {
		if r.IP != ips[i] {
			t.Errorf("result %d IP = %q, want %q", i, r.IP, ips[i])
		}
		nr, err := ParseOne(r.XMLBytes)
		if err != nil {
			t.Fatalf("synthetic XML didn't parse: %v", err)
		}
		if len(nr.Hosts) != 1 || nr.Hosts[0].Status.State != "up" {
			t.Errorf("result %d not parsed as one up host: %+v", i, nr.Hosts)
		}
		if len(nr.Hosts[0].Ports.List) != 0 {
			t.Errorf("result %d should have no ports", i)
		}
		var ip string
		for _, a := range nr.Hosts[0].Addresses {
			if a.AddrType == "ipv4" {
				ip = a.Addr
			}
		}
		if ip != ips[i] {
			t.Errorf("result %d parsed IP = %q, want %q", i, ip, ips[i])
		}
	}
}
