package vendor

import "strings"

// MACKind classifies a hardware address, so callers can explain *why* a vendor
// lookup came back empty instead of leaving a blank field.
type MACKind string

const (
	// KindGlobal is a real, IEEE-assigned address: the OUI identifies a vendor.
	KindGlobal MACKind = "global"
	// KindRandomized is a locally-administered address. Modern phones and
	// laptops randomize their MAC per network for privacy, so no vendor exists
	// to look up — an empty vendor here is correct, not a failed lookup.
	KindRandomized MACKind = "randomized"
	// KindMulticast is a group address, not a host.
	KindMulticast MACKind = "multicast"
	// KindUnknown means the value didn't parse as a MAC.
	KindUnknown MACKind = ""
)

// Classify inspects the two flag bits in the first octet of a MAC address.
//
// Bit 0 marks a multicast/group address; bit 1 marks a locally-administered
// one. Randomized privacy addresses set bit 1, which is why they never match an
// OUI: the IEEE never assigned them to anybody.
func Classify(mac string) MACKind {
	first, ok := firstOctet(mac)
	if !ok {
		return KindUnknown
	}
	switch {
	case first&0x01 != 0:
		return KindMulticast
	case first&0x02 != 0:
		return KindRandomized
	default:
		return KindGlobal
	}
}

// Describe returns a human-readable vendor string, falling back to an
// explanation when no vendor can exist rather than an empty value.
func Describe(db DB, mac string) string {
	if v := Lookup(db, mac, ""); v != "" {
		return v
	}
	switch Classify(mac) {
	case KindRandomized:
		return "randomized MAC (privacy)"
	case KindMulticast:
		return "multicast address"
	case KindUnknown:
		return ""
	default:
		return "unknown vendor"
	}
}

func firstOctet(mac string) (byte, bool) {
	mac = strings.TrimSpace(mac)
	if len(mac) < 2 {
		return 0, false
	}
	var v byte
	for i := 0; i < 2; i++ {
		c := mac[i]
		var d byte
		switch {
		case c >= '0' && c <= '9':
			d = c - '0'
		case c >= 'a' && c <= 'f':
			d = c - 'a' + 10
		case c >= 'A' && c <= 'F':
			d = c - 'A' + 10
		default:
			return 0, false
		}
		v = v<<4 | d
	}
	return v, true
}
