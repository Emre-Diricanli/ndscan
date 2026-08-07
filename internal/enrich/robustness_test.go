package enrich

import (
	"math/rand"
	"testing"
)

// A parser fed packets from the network must never panic or hang, whatever
// arrives. mDNS responses come from anything on the LAN, including hostile or
// simply broken implementations.
func TestParserSurvivesHostileInput(t *testing.T) {
	cases := [][]byte{
		{},
		{0x00},
		make([]byte, 11),                        // shorter than a DNS header
		{0, 0, 0x84, 0, 0, 0, 0, 1, 0, 0, 0, 0}, // claims an answer, has none
		// A compression pointer pointing at itself: the classic infinite loop.
		{0, 0, 0x84, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0xC0, 0x0C, 0, 12, 0, 1, 0, 0, 0, 0, 0, 0},
		// A pointer chain that walks backwards forever.
		{0, 0, 0x84, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0xC0, 0x0E, 0xC0, 0x0C, 0, 12, 0, 1, 0, 0, 0, 0, 0, 0},
		// Length byte claiming more data than the packet holds.
		{0, 0, 0x84, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0x3F, 'a', 'b'},
	}
	for i, c := range cases {
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("case %d panicked: %v", i, r)
				}
			}()
			_, _ = parseMDNSMessage(c)
			res := map[string]string{}
			absorbMDNSPacket(res, nil, c)
		}()
	}

	// Random garbage, since real networks produce stranger things than I can enumerate.
	rng := rand.New(rand.NewSource(1))
	for i := 0; i < 3000; i++ {
		b := make([]byte, rng.Intn(200))
		rng.Read(b)
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("random packet %d panicked: %v\n%v", i, r, b)
				}
			}()
			_, _ = parseMDNSMessage(b)
			absorbMDNSPacket(map[string]string{}, nil, b)
		}()
	}
}

func TestSSDPParserSurvivesHostileInput(t *testing.T) {
	rng := rand.New(rand.NewSource(2))
	for i := 0; i < 2000; i++ {
		b := make([]byte, rng.Intn(300))
		rng.Read(b)
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("random SSDP packet %d panicked: %v", i, r)
				}
			}()
			absorbSSDPPacket(map[string]string{}, nil, b)
		}()
	}
}
