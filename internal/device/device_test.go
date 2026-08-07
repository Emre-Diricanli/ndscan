package device

import (
	"reflect"
	"testing"
	"time"

	"github.com/Emre-Diricanli/ndscan/internal/ui"
	"github.com/Emre-Diricanli/ndscan/internal/vendor"
)

func TestKeyForGradesIdentity(t *testing.T) {
	cases := []struct {
		name       string
		ip, mac    string
		wantStable bool
		wantID     string
	}{
		// A globally-administered address is hardware identity: bit 1 of the
		// first octet clear.
		{"global mac", "192.0.2.1", "3c:22:fb:11:22:33", true, "mac:3c:22:fb:11:22:33"},
		// Formatting must not change the key — nmap, the ARP cache, and the
		// native sweep all report addresses differently.
		{"uppercase mac", "192.0.2.1", "3C:22:FB:11:22:33", true, "mac:3c:22:fb:11:22:33"},
		{"dashed mac", "192.0.2.1", "3c-22-fb-11-22-33", true, "mac:3c:22:fb:11:22:33"},
		{"bare mac", "192.0.2.1", "3c22fb112233", true, "mac:3c:22:fb:11:22:33"},
		// Randomized (locally-administered, bit 1 set) is worthless as lasting
		// identity: it changes on reconnection.
		{"randomized mac", "192.0.2.1", "02:11:22:33:44:55", false, "ip:192.0.2.1"},
		{"multicast", "192.0.2.1", "01:00:5e:00:00:01", false, "ip:192.0.2.1"},
		// A routed host has no MAC visible to us at all.
		{"no mac", "198.51.100.7", "", false, "ip:198.51.100.7"},
		{"garbage mac", "192.0.2.1", "not-a-mac", false, "ip:192.0.2.1"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			k := KeyFor(tc.ip, tc.mac)
			if k.ID != tc.wantID {
				t.Errorf("ID = %q, want %q", k.ID, tc.wantID)
			}
			if k.Stable() != tc.wantStable {
				t.Errorf("Stable() = %v, want %v", k.Stable(), tc.wantStable)
			}
		})
	}
}

// The same hardware on a new lease must stay one device, and a reused address
// must not merge two devices into one. This is the whole point of the package.
func TestIdentitySurvivesDHCP(t *testing.T) {
	mac := "3c:22:fb:11:22:33"
	first := KeyFor("192.0.2.10", mac)
	later := KeyFor("192.0.2.99", mac) // same laptop, new lease
	if first.ID != later.ID {
		t.Errorf("a device that changed address became a different device: %q vs %q", first.ID, later.ID)
	}

	// The address it vacated later belongs to something else entirely.
	other := KeyFor("192.0.2.10", "b8:27:eb:aa:bb:cc")
	if other.ID == first.ID {
		t.Error("two devices that shared an address collapsed into one identity")
	}
}

// A randomized MAC is stable only for as long as the device stays put. Keying
// on it would mint a new device per reconnection and grow the list forever.
func TestRandomizedMACDoesNotBecomeIdentity(t *testing.T) {
	a := KeyFor("192.0.2.5", "02:aa:bb:cc:dd:01")
	b := KeyFor("192.0.2.5", "02:aa:bb:cc:dd:02") // same host, re-randomized
	if a.ID != b.ID {
		t.Errorf("re-randomizing changed the key: %q vs %q", a.ID, b.ID)
	}
	if a.Stable() {
		t.Error("a randomized MAC must not be reported as stable identity")
	}
}

func TestRecordSeenAccumulatesHistory(t *testing.T) {
	t0 := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	r := Record{}.Seen(t0, "192.0.2.1", "laptop")
	r = r.Seen(t0.Add(time.Hour), "192.0.2.9", "laptop")

	if !r.FirstSeen.Equal(t0) {
		t.Errorf("FirstSeen = %v, want %v", r.FirstSeen, t0)
	}
	if !r.LastSeen.Equal(t0.Add(time.Hour)) {
		t.Errorf("LastSeen = %v, want the later observation", r.LastSeen)
	}
	// Most recent first, and the old address retained.
	if !reflect.DeepEqual(r.Addresses, []string{"192.0.2.9", "192.0.2.1"}) {
		t.Errorf("Addresses = %v, want the new address first and the old kept", r.Addresses)
	}
	// A repeated hostname must not accumulate duplicates.
	if len(r.Hostnames) != 1 {
		t.Errorf("Hostnames = %v, want one entry", r.Hostnames)
	}
}

// An out-of-order observation (a replayed or late-arriving scan) must not move
// FirstSeen forward or LastSeen backward.
func TestRecordSeenToleratesOutOfOrder(t *testing.T) {
	t0 := time.Date(2026, 1, 2, 0, 0, 0, 0, time.UTC)
	r := Record{}.Seen(t0, "192.0.2.1", "")
	r = r.Seen(t0.Add(-24*time.Hour), "192.0.2.1", "")

	if !r.FirstSeen.Equal(t0.Add(-24 * time.Hour)) {
		t.Errorf("FirstSeen = %v, want the earlier time", r.FirstSeen)
	}
	if !r.LastSeen.Equal(t0) {
		t.Errorf("LastSeen = %v, want the later time", r.LastSeen)
	}
}

func TestRecordHistoryIsBounded(t *testing.T) {
	at := time.Now()
	r := Record{}
	for i := 0; i < maxAddresses*3; i++ {
		r = r.Seen(at, "192.0.2."+string(rune('0'+i%10))+"x", "")
	}
	if len(r.Addresses) > maxAddresses {
		t.Errorf("addresses grew to %d, want at most %d", len(r.Addresses), maxAddresses)
	}
}

// A user-assigned name is a decision. Nothing the device advertises later may
// overwrite it.
func TestLabelPrecedence(t *testing.T) {
	cases := []struct {
		name string
		rec  Record
		want string
	}{
		{"user name wins", Record{Name: "kids-tablet", Hostnames: []string{"android-1234"}, Addresses: []string{"192.0.2.1"}}, "kids-tablet"},
		{"then advertised name", Record{Hostnames: []string{"Living-Room-TV"}, Addresses: []string{"192.0.2.1"}}, "Living-Room-TV"},
		{"then vendor and address", Record{Vendor: "Ubiquiti", Addresses: []string{"192.0.2.1"}}, "Ubiquiti (192.0.2.1)"},
		{"then address", Record{Addresses: []string{"192.0.2.1"}}, "192.0.2.1"},
		{"finally the key", Record{Key: "ip:192.0.2.1"}, "ip:192.0.2.1"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.rec.Label(); got != tc.want {
				t.Errorf("Label() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestFromRowsSkipsDownHosts(t *testing.T) {
	at := time.Now()
	rows := []ui.Row{
		{IP: "192.0.2.1", Up: true, MAC: "3c:22:fb:11:22:33"},
		{IP: "192.0.2.2", Up: false}, // did not answer: says nothing about identity
		{IP: "192.0.2.3", Up: true},  // MAC only in the ARP cache
	}
	obs := FromRows(rows, map[string]string{"192.0.2.3": "b8:27:eb:aa:bb:cc"}, at)

	if len(obs) != 2 {
		t.Fatalf("observations = %d, want 2 (down hosts excluded): %+v", len(obs), obs)
	}
	// The ARP cache must fill in a MAC the row lacked, or we downgrade identity
	// for exactly the local devices we can identify best.
	if obs[1].MAC != "b8:27:eb:aa:bb:cc" {
		t.Errorf("ARP-supplied MAC lost: %+v", obs[1])
	}
}

func TestApplyReportsNewDevices(t *testing.T) {
	at := time.Now()
	oui := vendor.DB{}

	devices, added := Apply(nil, []Observation{
		{IP: "192.0.2.1", MAC: "3c:22:fb:11:22:33", Hostname: "nas", At: at},
	}, oui)
	if len(added) != 1 {
		t.Fatalf("added = %v, want one new device", added)
	}
	if len(devices) != 1 {
		t.Fatalf("devices = %d, want 1", len(devices))
	}

	// Seeing it again is not a new device, even on a different address.
	devices, added = Apply(devices, []Observation{
		{IP: "192.0.2.50", MAC: "3c:22:fb:11:22:33", Hostname: "nas", At: at.Add(time.Hour)},
	}, oui)
	if len(added) != 0 {
		t.Errorf("a known device on a new lease was reported as new: %v", added)
	}
	if len(devices) != 1 {
		t.Errorf("devices = %d, want the same one device", len(devices))
	}
	for _, r := range devices {
		if len(r.Addresses) != 2 {
			t.Errorf("addresses = %v, want both leases recorded", r.Addresses)
		}
	}
}
