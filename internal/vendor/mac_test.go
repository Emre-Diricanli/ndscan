package vendor

import "testing"

func TestClassify(t *testing.T) {
	cases := []struct {
		mac  string
		want MACKind
	}{
		// Real IEEE-assigned addresses (bit 1 clear).
		{"6c:63:f8:aa:d8:c9", KindGlobal}, // Ubiquiti
		{"98:7a:9b:1e:88:82", KindGlobal}, // TCL
		{"a4:83:e7:00:00:00", KindGlobal}, // Apple
		// Locally administered => randomized privacy address.
		{"f2:a8:74:5d:c3:8c", KindRandomized},
		{"26:75:c1:18:5e:9d", KindRandomized},
		{"d6:55:37:bd:bd:b8", KindRandomized},
		// Group bit set.
		{"01:00:5e:00:00:01", KindMulticast},
		{"33:33:00:00:00:01", KindMulticast},
		// Garbage.
		{"", KindUnknown},
		{"zz:zz", KindUnknown},
	}
	for _, c := range cases {
		if got := Classify(c.mac); got != c.want {
			t.Errorf("Classify(%q) = %q, want %q", c.mac, got, c.want)
		}
	}
}

// A blank vendor should explain itself rather than looking like a failure.
//
// The database is supplied explicitly rather than via LoadDefault: nmap's OUI
// file is not present on CI runners, so depending on it would make this test
// pass or fail based on the machine rather than the behaviour under test.
func TestDescribe(t *testing.T) {
	db := DB{"6C63F8": "Ubiquiti"}

	if got := Describe(db, "6c:63:f8:aa:d8:c9"); got != "Ubiquiti" {
		t.Errorf("known OUI = %q, want Ubiquiti", got)
	}
	if got := Describe(db, "f2:a8:74:5d:c3:8c"); got != "randomized MAC (privacy)" {
		t.Errorf("randomized MAC = %q, want the privacy explanation", got)
	}
	if got := Describe(db, "01:00:5e:00:00:01"); got != "multicast address" {
		t.Errorf("multicast = %q", got)
	}
	if got := Describe(db, ""); got != "" {
		t.Errorf("empty MAC should describe as empty, got %q", got)
	}
}
