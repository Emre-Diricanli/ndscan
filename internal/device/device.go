// Package device gives the hosts on a network a stable identity that survives
// DHCP.
//
// Everything else in ndscan is keyed by IP, which is the one property of a
// device guaranteed to change. A laptop that reconnects on a new lease looks
// like a departure and an arrival; the same address handed to a printer next
// week looks like a machine that grew a print service. Neither reading is what
// happened, and no amount of care in the diff can recover the truth from
// addresses alone.
//
// A hardware address is the better key, but it is not a universal one: it is
// only visible for hosts on the same layer 2 segment, and modern phones and
// laptops randomize it per network for privacy. So identity here is explicitly
// graded — Key reports both an identifier and how much that identifier is
// worth, and callers that persist history are expected to check.
package device

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/Emre-Diricanli/ndscan/internal/ui"
	"github.com/Emre-Diricanli/ndscan/internal/vendor"
)

// Confidence describes how much a device key can be trusted to mean "the same
// physical thing" across scans.
type Confidence int

const (
	// Stable: keyed by a globally-administered MAC. The IEEE assigned it to a
	// manufacturer and it stays with the hardware, so this key follows a device
	// across leases, subnets, and reboots.
	Stable Confidence = iota
	// Ephemeral: keyed by IP because no usable MAC was available — the host is
	// routed rather than on our segment, or it randomizes its address. The key
	// is still useful within a session but must not be treated as a lasting
	// identity: the next lease will produce a different one.
	Ephemeral
)

func (c Confidence) String() string {
	if c == Stable {
		return "stable"
	}
	return "ephemeral"
}

// Key is a device's identity plus how far that identity can be trusted.
type Key struct {
	// ID is the opaque string other packages store. It is prefixed by kind so
	// a MAC-derived key and an IP-derived one can never collide.
	ID         string
	Confidence Confidence
	// MAC is the hardware address the key came from, empty for Ephemeral keys.
	MAC string
}

// Stable reports whether this key identifies hardware rather than an address.
//
// Callers that write durable history should check this: recording a device's
// first-seen date under an ephemeral key promises continuity the key cannot
// deliver, and the record becomes a lie the next time DHCP moves the host.
func (k Key) Stable() bool { return k.Confidence == Stable }

// KeyFor derives a device key from an address and whatever MAC we learned.
//
// A randomized MAC is deliberately treated as no MAC at all. It is stable for
// as long as the device stays on this network and worthless afterwards, and
// treating it as hardware identity would silently accumulate one "device" per
// reconnection — a device list that grows without bound and describes nobody.
func KeyFor(ip, mac string) Key {
	if vendor.Classify(mac) == vendor.KindGlobal {
		return Key{ID: "mac:" + normalizeMAC(mac), Confidence: Stable, MAC: normalizeMAC(mac)}
	}
	return Key{ID: "ip:" + ip, Confidence: Ephemeral}
}

// normalizeMAC lowercases and colon-separates an address so the same hardware
// produces the same key regardless of which tool reported it. nmap, the ARP
// cache, and the native sweep do not agree on formatting.
func normalizeMAC(mac string) string {
	clean := strings.Map(func(r rune) rune {
		switch {
		case r >= '0' && r <= '9', r >= 'a' && r <= 'f':
			return r
		case r >= 'A' && r <= 'F':
			return r + ('a' - 'A')
		}
		return -1
	}, mac)
	if len(clean) != 12 {
		return strings.ToLower(strings.TrimSpace(mac))
	}
	var b strings.Builder
	for i := 0; i < 12; i += 2 {
		if i > 0 {
			b.WriteByte(':')
		}
		b.WriteString(clean[i : i+2])
	}
	return b.String()
}

// Record is what we know about one device across every scan that has seen it.
type Record struct {
	Key        string    `json:"key"`
	MAC        string    `json:"mac,omitempty"`
	Vendor     string    `json:"vendor,omitempty"`
	Confidence string    `json:"confidence"`
	FirstSeen  time.Time `json:"firstSeen"`
	LastSeen   time.Time `json:"lastSeen"`
	// Name is a label the user assigned. It always wins over discovered names:
	// a person who took the trouble to call something "kids-tablet" should not
	// have it renamed by whatever the device advertises next.
	Name string `json:"name,omitempty"`
	// Hostnames are names the device has gone by, most recent first. Keeping
	// the history rather than one current value is what lets a rename read as a
	// rename instead of a new device.
	Hostnames []string `json:"hostnames,omitempty"`
	// Addresses are IPs this device has held, most recent first.
	Addresses []string `json:"addresses,omitempty"`
}

// Label is the best human-readable name for this device.
//
// Precedence is deliberate: what the user called it, then what it called
// itself, then what its hardware vendor is, then its address. Each fallback is
// strictly less informative than the last, so the first non-empty one wins.
func (r Record) Label() string {
	switch {
	case r.Name != "":
		return r.Name
	case len(r.Hostnames) > 0:
		return r.Hostnames[0]
	case r.Vendor != "" && len(r.Addresses) > 0:
		return fmt.Sprintf("%s (%s)", r.Vendor, r.Addresses[0])
	case len(r.Addresses) > 0:
		return r.Addresses[0]
	}
	return r.Key
}

// Seen folds one observation into a record, returning the updated value.
//
// It is additive on purpose: a device that answers on a new address keeps the
// old one in its history rather than replacing it, because "this machine has
// held three addresses this month" is exactly the kind of fact the record
// exists to preserve.
func (r Record) Seen(at time.Time, ip, hostname string) Record {
	at = at.UTC()
	if r.FirstSeen.IsZero() || at.Before(r.FirstSeen) {
		r.FirstSeen = at
	}
	if at.After(r.LastSeen) {
		r.LastSeen = at
	}
	if ip != "" {
		r.Addresses = promote(r.Addresses, ip, maxAddresses)
	}
	if hostname != "" {
		r.Hostnames = promote(r.Hostnames, hostname, maxHostnames)
	}
	return r
}

// How much history to keep per field. These are generous for a home or office
// network and bounded so a device on a pathological DHCP setup cannot grow its
// record without limit.
const (
	maxAddresses = 10
	maxHostnames = 5
)

// promote moves v to the front of the list, keeping the rest in order and
// dropping the oldest entry past the limit. Most-recent-first ordering is what
// makes Label's "current name" cheap.
func promote(list []string, v string, limit int) []string {
	out := make([]string, 0, len(list)+1)
	out = append(out, v)
	for _, existing := range list {
		if existing == v {
			continue
		}
		out = append(out, existing)
	}
	if len(out) > limit {
		out = out[:limit]
	}
	return out
}

// Observation is one host as a single scan saw it.
type Observation struct {
	IP       string
	MAC      string
	Hostname string
	At       time.Time
}

// FromRows turns a finished scan's rows into observations.
//
// macs supplies addresses the scan learned out of band — the ARP cache knows
// hardware addresses for hosts whose rows carry none, and dropping that would
// downgrade identity for exactly the local devices we can identify best.
func FromRows(rows []ui.Row, macs map[string]string, at time.Time) []Observation {
	out := make([]Observation, 0, len(rows))
	for _, r := range rows {
		if !r.Up {
			continue // a host that did not answer says nothing about identity
		}
		mac := r.MAC
		if mac == "" {
			mac = macs[r.IP]
		}
		out = append(out, Observation{IP: r.IP, MAC: mac, Hostname: r.Host, At: at})
	}
	return out
}

// Apply folds a scan's observations into a device set, returning the updated
// records and the keys that were seen for the first time.
//
// New keys are reported separately because "a device we have never seen joined
// the network" is the event worth alerting on, and it cannot be recovered later
// from the records alone — by then it has a first-seen date like every other.
func Apply(existing map[string]Record, obs []Observation, oui vendor.DB) (map[string]Record, []string) {
	out := make(map[string]Record, len(existing)+len(obs))
	for k, v := range existing {
		out[k] = v
	}
	var added []string
	for _, o := range obs {
		key := KeyFor(o.IP, o.MAC)
		rec, known := out[key.ID]
		if !known {
			rec = Record{Key: key.ID, Confidence: key.Confidence.String()}
			added = append(added, key.ID)
		}
		if key.MAC != "" {
			rec.MAC = key.MAC
			if v := vendor.Lookup(oui, key.MAC, ""); v != "" {
				rec.Vendor = v
			}
		}
		out[key.ID] = rec.Seen(o.At, o.IP, o.Hostname)
	}
	sort.Strings(added)
	return out, added
}
