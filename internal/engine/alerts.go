package engine

import (
	"encoding/json"
	"os"
	"path/filepath"
	"time"

	"github.com/Emre-Diricanli/ndscan/internal/alert"
	"github.com/Emre-Diricanli/ndscan/internal/config"
)

// gatewayState is the small amount of cross-scan memory the ARP-spoof canary
// needs: what the gateway's hardware address was last time we looked.
//
// It lives in its own file rather than in the device store because the gateway
// is not a device record — we track it by role, and the whole point is to
// notice when the hardware behind that role changes.
type gatewayState struct {
	IP   string    `json:"ip"`
	MAC  string    `json:"mac"`
	Seen time.Time `json:"seen"`
}

func gatewayStatePath() string { return filepath.Join(config.Dir(), "gateway.json") }

func loadGatewayState() gatewayState {
	var g gatewayState
	b, err := os.ReadFile(gatewayStatePath())
	if err != nil {
		return g
	}
	_ = json.Unmarshal(b, &g)
	return g
}

func saveGatewayState(g gatewayState) error {
	b, err := json.MarshalIndent(g, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(config.Dir(), 0o755); err != nil {
		return err
	}
	return config.WriteFileAtomic(gatewayStatePath(), b, 0o644)
}

// evaluateAlerts turns a finished scan's changes into things worth telling a
// person, and remembers what it needs to do that again next time.
//
// It runs inside Persist because that is where the diff, the device set, and
// the newly-seen keys already exist. Computing them a second time in each front
// end is how the three of them drifted apart on history handling, and alerts
// would drift the same way.
func (e *Engine) evaluateAlerts(rec *Record, out Outcome, gatewayIP string, now time.Time) []alert.Alert {
	// The gateway's MAC comes from this scan's own ARP data rather than a
	// separate lookup: it is the address we actually observed while scanning,
	// which is the one an attacker would have had to poison.
	var curMAC string
	if gatewayIP != "" {
		curMAC = out.MACs[gatewayIP]
	}

	prev := loadGatewayState()
	prevMAC := prev.MAC
	// A gateway change is only meaningful against the same gateway. Roaming to
	// a different network entirely gives a different IP, and comparing across
	// those would report a spoof every time the user changes Wi-Fi.
	if prev.IP != gatewayIP {
		prevMAC = ""
	}

	alerts := alert.Evaluate(alert.Load(), rec.Diff, rec.Devices, rec.NewDevices, curMAC, prevMAC, now)

	if curMAC != "" {
		if err := saveGatewayState(gatewayState{IP: gatewayIP, MAC: curMAC, Seen: now}); err != nil {
			rec.Warnings = append(rec.Warnings, "gateway state could not be saved: "+err.Error())
		}
	}
	return alerts
}
