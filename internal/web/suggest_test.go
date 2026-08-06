package web

import (
	"encoding/json"
	"net/http"
	"testing"
)

// A machine typically has many more interfaces than networks worth scanning.
// Offering tunnels and link-local virtuals as targets would bury the one
// network the user actually means.
func TestScannableInterface(t *testing.T) {
	scannable := []string{"en0", "en1", "eth0", "wlan0", "enp3s0"}
	for _, name := range scannable {
		if !scannableInterface(name) {
			t.Errorf("scannableInterface(%q) = false, want true", name)
		}
	}

	// utun*: VPN/point-to-point. awdl*/llw*: Apple peer-to-peer link-local.
	// bridge*: virtual. gif*/stf*: tunnel pseudo-devices. ap*: hosted AP.
	skipped := []string{"utun0", "utun8", "awdl0", "llw0", "bridge0", "gif0", "stf0", "ap1"}
	for _, name := range skipped {
		if scannableInterface(name) {
			t.Errorf("scannableInterface(%q) = true, want false", name)
		}
	}
}

// Suggestions must never include a prefix with no other hosts in it — a /31 or
// /32 is a point-to-point or single-address link, so sweeping it finds nothing.
func TestSuggestedNetworks_ExcludesUnsweepablePrefixes(t *testing.T) {
	for _, n := range suggestedNetworks() {
		if n.CIDR == "" {
			t.Error("suggested network has empty CIDR")
		}
		if !scannableInterface(n.Interface) {
			t.Errorf("suggested %s on non-scannable interface %s", n.CIDR, n.Interface)
		}
	}
}

// The UI prefills from this field, so it has to survive the round trip.
func TestState_IncludesSuggestedNetworks(t *testing.T) {
	s := NewServer("test")
	srv := startServer(t, s)

	resp, err := http.Get(srv.URL + "/api/state")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	var st stateResponse
	if err := json.NewDecoder(resp.Body).Decode(&st); err != nil {
		t.Fatal(err)
	}
	// The count depends on the host running the test, so assert the shape
	// rather than a number: a CI container may legitimately have none.
	for _, n := range st.Suggested {
		if n.CIDR == "" || n.Interface == "" {
			t.Errorf("incomplete suggestion: %+v", n)
		}
	}
}
