package web

import (
	"encoding/json"
	"net/http"
	"reflect"
	"slices"
	"testing"

	"github.com/Emre-Diricanli/ndscan/internal/netinfo"
)

func TestRoutedSweepTargets(t *testing.T) {
	tests := []struct {
		name       string
		locals     []netinfo.Network
		extra      []string
		wantPrefix []string
		wantCount  int
	}{
		{
			name: "attached network and derived siblings",
			locals: []netinfo.Network{
				{Interface: "en0", CIDR: "192.168.7.0/24", Addr: "192.168.7.4"},
				{Interface: "utun2", CIDR: "10.8.0.2/32", Addr: "10.8.0.2"},
			},
			wantPrefix: []string{"192.168.7.0/24"},
			wantCount:  12,
		},
		{
			name:       "explicit candidate without an attached twenty-four",
			locals:     []netinfo.Network{{Interface: "utun2", CIDR: "10.8.0.2/32", Addr: "10.8.0.2"}},
			extra:      []string{"192.168.100.0/24"},
			wantPrefix: nil,
			wantCount:  1,
		},
		{
			name:       "no candidates",
			locals:     []netinfo.Network{{Interface: "utun2", CIDR: "10.8.0.2/32", Addr: "10.8.0.2"}},
			wantPrefix: nil,
			wantCount:  0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, count := routedSweepTargets(tt.locals, tt.extra)
			if count != tt.wantCount {
				t.Fatalf("candidate count = %d, want %d (targets %v)", count, tt.wantCount, got)
			}
			if !slices.Equal(got[:len(tt.wantPrefix)], tt.wantPrefix) {
				t.Errorf("target prefix = %v, want %v", got[:len(tt.wantPrefix)], tt.wantPrefix)
			}
			for _, target := range got {
				if target == "10.8.0.2/32" {
					t.Error("/32 local was included")
				}
			}
		})
	}
}

func TestSweepRejectsInvalidExtra(t *testing.T) {
	srv := newTestServer(t)
	resp := postJSON(t, srv, "/api/scan/sweep", `{"extra":["--script=bad"]}`)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", resp.StatusCode)
	}
}

func TestSweepRejectsConcurrentScan(t *testing.T) {
	if len(netinfo.SiblingCandidates(netinfo.Locals(), []string{"192.168.100.0/24"})) == 0 {
		t.Fatal("explicit candidate unexpectedly omitted")
	}
	s := NewServer("test")
	s.mu.Lock()
	s.scanning = true
	s.cancel = func() {}
	s.mu.Unlock()
	srv := startServer(t, s)

	resp := postJSON(t, srv, "/api/scan/sweep", `{"extra":["192.168.100.0/24"]}`)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusConflict {
		t.Fatalf("status = %d, want 409", resp.StatusCode)
	}
}

func TestStateIncludesSiblingCandidates(t *testing.T) {
	srv := newTestServer(t)
	resp, err := http.Get(srv.URL + "/api/state")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	var got stateResponse
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatal(err)
	}
	want := netinfo.SiblingCandidates(netinfo.Locals(), nil)
	if !reflect.DeepEqual(got.Siblings, want) {
		t.Errorf("siblings = %v, want %v", got.Siblings, want)
	}
}
