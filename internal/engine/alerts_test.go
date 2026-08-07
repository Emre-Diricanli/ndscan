package engine

import (
	"testing"
	"time"

	"github.com/Emre-Diricanli/ndscan/internal/ui"
	"github.com/Emre-Diricanli/ndscan/internal/vendor"
)

// The chain this wave exists to close: a scan finds a device that was not there
// before, and something reaches the user about it.
func TestNewDeviceReachesTheUserAsAnAlert(t *testing.T) {
	t.Setenv("NDSCAN_CONFIG_DIR", t.TempDir())
	e := New()
	t0 := time.Now().Add(-time.Hour)

	// Baseline: one known host.
	e.Persist(complete(
		ui.Row{IP: "192.0.2.1", Up: true, MAC: "3c:22:fb:11:22:33"},
	), recordPlan(), t0, vendor.DB{})

	// A second device appears.
	rec := e.Persist(complete(
		ui.Row{IP: "192.0.2.1", Up: true, MAC: "3c:22:fb:11:22:33"},
		ui.Row{IP: "192.0.2.9", Up: true, MAC: "b8:27:eb:aa:bb:cc"},
	), recordPlan(), t0.Add(time.Hour), vendor.DB{})

	if len(rec.Alerts) == 0 {
		t.Fatal("a new device produced no alert: the chain is not connected")
	}
	var found bool
	for _, a := range rec.Alerts {
		if a.Rule == "new-device" {
			found = true
			if a.Title == "" || a.Body == "" {
				t.Errorf("alert has no message to show: %+v", a)
			}
		}
	}
	if !found {
		t.Errorf("alerts = %+v, want a new-device alert", rec.Alerts)
	}
}

// A phone that keeps dropping off Wi-Fi and rejoining looks like a departure
// and an arrival every few minutes. The device store cannot suppress that — the
// device really is leaving and returning — so the suppressor has to, or watch
// mode notifies all afternoon about one restless handset.
func TestFlappingDeviceIsReportedOnce(t *testing.T) {
	t.Setenv("NDSCAN_CONFIG_DIR", t.TempDir())
	e := New()
	t0 := time.Now().Add(-2 * time.Hour)

	present := complete(
		ui.Row{IP: "192.0.2.1", Up: true, MAC: "3c:22:fb:11:22:33"},
		ui.Row{IP: "192.0.2.9", Up: true, MAC: "b8:27:eb:aa:bb:cc"},
	)
	absent := complete(ui.Row{IP: "192.0.2.1", Up: true, MAC: "3c:22:fb:11:22:33"})

	e.Persist(present, recordPlan(), t0, vendor.DB{})

	total := 0
	// Five leave/rejoin cycles, one every couple of minutes. Both halves count:
	// a user receives the departure notification as well as the return.
	for i := 0; i < 5; i++ {
		at := t0.Add(time.Duration(i*2+1) * time.Minute)
		total += len(e.Persist(absent, recordPlan(), at, vendor.DB{}).Alerts)
		total += len(e.Persist(present, recordPlan(), at.Add(time.Minute), vendor.DB{}).Alerts)
	}
	if total > 1 {
		t.Errorf("a flapping device produced %d alerts, want at most 1 within the cooldown", total)
	}
}

// A run that cannot be trusted has no diff, so it must produce no alerts —
// otherwise a cancelled scan reports the whole network as having vanished.
func TestIncompleteRunRaisesNoAlerts(t *testing.T) {
	t.Setenv("NDSCAN_CONFIG_DIR", t.TempDir())
	e := New()
	now := time.Now()

	e.Persist(complete(ui.Row{IP: "192.0.2.1", Up: true, MAC: "3c:22:fb:11:22:33"}), recordPlan(), now, vendor.DB{})
	rec := e.Persist(Outcome{Status: StatusCancelled}, recordPlan(), now.Add(time.Minute), vendor.DB{})

	if len(rec.Alerts) != 0 {
		t.Errorf("a cancelled scan raised %d alerts: %+v", len(rec.Alerts), rec.Alerts)
	}
}

// The ARP-spoof canary: the hardware answering for the gateway changed.
func TestGatewayMACChangeAlerts(t *testing.T) {
	t.Setenv("NDSCAN_CONFIG_DIR", t.TempDir())
	e := New()
	t0 := time.Now().Add(-time.Hour)
	gw := "192.0.2.254"

	first := complete(ui.Row{IP: "192.0.2.1", Up: true, MAC: "3c:22:fb:11:22:33"})
	first.MACs = map[string]string{gw: "6c:63:f8:aa:d8:c9"}
	e.PersistWithGateway(first, recordPlan(), t0, vendor.DB{}, gw)

	// Same network, same gateway address, different hardware behind it.
	second := complete(ui.Row{IP: "192.0.2.1", Up: true, MAC: "3c:22:fb:11:22:33"})
	second.MACs = map[string]string{gw: "de:ad:be:ef:00:01"}
	rec := e.PersistWithGateway(second, recordPlan(), t0.Add(time.Hour), vendor.DB{}, gw)

	var got bool
	for _, a := range rec.Alerts {
		if a.Rule == "gateway-mac-changed" {
			got = true
			if a.Severity != "high" {
				t.Errorf("severity = %q, want high for a possible ARP spoof", a.Severity)
			}
		}
	}
	if !got {
		t.Errorf("a changed gateway MAC raised no alert: %+v", rec.Alerts)
	}
}

// Roaming to a different network gives a different gateway address. Comparing
// across those would report a spoof every time the user changes Wi-Fi.
func TestRoamingToANewNetworkIsNotASpoof(t *testing.T) {
	t.Setenv("NDSCAN_CONFIG_DIR", t.TempDir())
	e := New()
	t0 := time.Now().Add(-time.Hour)

	home := complete(ui.Row{IP: "192.0.2.1", Up: true, MAC: "3c:22:fb:11:22:33"})
	home.MACs = map[string]string{"192.0.2.254": "6c:63:f8:aa:d8:c9"}
	e.PersistWithGateway(home, recordPlan(), t0, vendor.DB{}, "192.0.2.254")

	// A different network entirely: different gateway IP, different hardware.
	cafe := complete(ui.Row{IP: "192.0.2.1", Up: true, MAC: "3c:22:fb:11:22:33"})
	cafe.MACs = map[string]string{"198.51.100.1": "de:ad:be:ef:00:01"}
	rec := e.PersistWithGateway(cafe, recordPlan(), t0.Add(time.Hour), vendor.DB{}, "198.51.100.1")

	for _, a := range rec.Alerts {
		if a.Rule == "gateway-mac-changed" {
			t.Errorf("changing networks was reported as an ARP spoof: %+v", a)
		}
	}
}

// A fresh install sees every host on the network as new. That is the moment we
// started looking, not a set of arrivals — a small home network produced four
// notifications on its first run, which is how a person learns to turn
// alerting off entirely.
func TestFirstInventoryDoesNotStorm(t *testing.T) {
	t.Setenv("NDSCAN_CONFIG_DIR", t.TempDir())
	e := New()

	rec := e.Persist(complete(
		ui.Row{IP: "192.0.2.1", Up: true, MAC: "3c:22:fb:11:22:33"},
		ui.Row{IP: "192.0.2.2", Up: true, MAC: "b8:27:eb:aa:bb:cc"},
		ui.Row{IP: "192.0.2.3", Up: true, MAC: "a0:85:27:2f:9a:27"},
		ui.Row{IP: "192.0.2.4", Up: true, MAC: "b0:be:83:50:58:b3"},
	), recordPlan(), time.Now(), vendor.DB{})

	for _, a := range rec.Alerts {
		if a.Rule == "new-device" {
			t.Errorf("the first inventory announced an arrival: %+v", a)
		}
	}
	// The devices are still learned — we know they exist, we just have no
	// evidence that any of them just showed up.
	if len(rec.Devices) != 4 {
		t.Errorf("devices = %d, want 4 learned on the first scan", len(rec.Devices))
	}
}

// Once an inventory exists, a genuinely new device must still alert — the
// suppression above must not swallow the signal it was meant to protect.
func TestArrivalAfterFirstInventoryStillAlerts(t *testing.T) {
	t.Setenv("NDSCAN_CONFIG_DIR", t.TempDir())
	e := New()
	t0 := time.Now().Add(-time.Hour)

	e.Persist(complete(ui.Row{IP: "192.0.2.1", Up: true, MAC: "3c:22:fb:11:22:33"}),
		recordPlan(), t0, vendor.DB{})

	rec := e.Persist(complete(
		ui.Row{IP: "192.0.2.1", Up: true, MAC: "3c:22:fb:11:22:33"},
		ui.Row{IP: "192.0.2.9", Up: true, MAC: "b8:27:eb:aa:bb:cc"},
	), recordPlan(), t0.Add(time.Hour), vendor.DB{})

	var got bool
	for _, a := range rec.Alerts {
		if a.Rule == "new-device" {
			got = true
		}
	}
	if !got {
		t.Errorf("a real arrival was suppressed: %+v", rec.Alerts)
	}
}
