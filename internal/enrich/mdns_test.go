package enrich

import (
	"context"
	"encoding/binary"
	"net"
	"reflect"
	"testing"
	"time"
)

func TestEncodeName(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want []byte
	}{
		{"dotted", "foo.local", []byte{3, 'f', 'o', 'o', 5, 'l', 'o', 'c', 'a', 'l', 0}},
		{"trailing dot trimmed", "foo.local.", []byte{3, 'f', 'o', 'o', 5, 'l', 'o', 'c', 'a', 'l', 0}},
		{"root", "", []byte{0}},
		{"single label", "tv", []byte{2, 't', 'v', 0}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := encodeName(tt.in); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("encodeName(%q) = %v, want %v", tt.in, got, tt.want)
			}
		})
	}
}

func TestBuildMDNSQuery(t *testing.T) {
	types := []string{"_airplay._tcp.local", "_ssh._tcp.local"}
	msg := buildMDNSQuery(types, false)

	if got := binary.BigEndian.Uint16(msg[0:2]); got != 0 {
		t.Errorf("query ID = %d, want 0 per RFC 6762", got)
	}
	if got := binary.BigEndian.Uint16(msg[2:4]); got != 0 {
		t.Errorf("flags = %#x, want 0 for a plain query", got)
	}
	if got := int(binary.BigEndian.Uint16(msg[4:6])); got != len(types)+1 {
		t.Fatalf("QDCOUNT = %d, want %d", got, len(types)+1)
	}

	// Walk the questions back out and verify names, types, and classes.
	off := dnsHeaderLen
	wantNames := append([]string{"_services._dns-sd._udp.local"}, types...)
	for i, want := range wantNames {
		name, next, err := parseName(msg, off)
		if err != nil {
			t.Fatalf("question %d: %v", i, err)
		}
		if name != want {
			t.Errorf("question %d name = %q, want %q", i, name, want)
		}
		if qtype := binary.BigEndian.Uint16(msg[next : next+2]); qtype != dnsTypePTR {
			t.Errorf("question %d type = %d, want PTR", i, qtype)
		}
		if class := binary.BigEndian.Uint16(msg[next+2 : next+4]); class != dnsClassIN {
			t.Errorf("question %d class = %#x, want IN without QU bit", i, class)
		}
		off = next + 4
	}
}

func TestBuildMDNSQueryUnicastBit(t *testing.T) {
	msg := buildMDNSQuery([]string{"_ssh._tcp.local"}, true)
	off := dnsHeaderLen
	for i := range 2 {
		_, next, err := parseName(msg, off)
		if err != nil {
			t.Fatalf("question %d: %v", i, err)
		}
		if class := binary.BigEndian.Uint16(msg[next+2 : next+4]); class&0x8000 == 0 {
			t.Errorf("question %d class = %#x, want QU bit set", i, class)
		}
		off = next + 4
	}
}

func TestParseName(t *testing.T) {
	// Question at offset 12 holds 'foo.local'; a record name later uses a
	// compression pointer back to it, which is how real responders answer.
	msg := make([]byte, dnsHeaderLen)
	msg = append(msg, encodeName("foo.local")...)
	ptrOff := len(msg)
	msg = append(msg, 0xC0, byte(dnsHeaderLen))

	t.Run("plain", func(t *testing.T) {
		name, next, err := parseName(msg, dnsHeaderLen)
		if err != nil {
			t.Fatal(err)
		}
		if name != "foo.local" || next != ptrOff {
			t.Errorf("got (%q, %d), want (foo.local, %d)", name, next, ptrOff)
		}
	})
	t.Run("compression pointer", func(t *testing.T) {
		name, next, err := parseName(msg, ptrOff)
		if err != nil {
			t.Fatal(err)
		}
		if name != "foo.local" || next != ptrOff+2 {
			t.Errorf("got (%q, %d), want (foo.local, %d)", name, next, ptrOff+2)
		}
	})
	t.Run("pointer loop", func(t *testing.T) {
		loop := []byte{0xC0, 0x00} // points at itself
		if _, _, err := parseName(loop, 0); err == nil {
			t.Error("expected error for pointer loop")
		}
	})
	t.Run("truncated", func(t *testing.T) {
		if _, _, err := parseName([]byte{3, 'f'}, 0); err == nil {
			t.Error("expected error for truncated label")
		}
	})
	t.Run("out of bounds", func(t *testing.T) {
		if _, _, err := parseName(msg, len(msg)+5); err == nil {
			t.Error("expected error for offset past end")
		}
	})
}

// mdnsResponse builds a wire-format response: one PTR answer naming instance
// (e.g. 'TV._airplay._tcp.local') and, when ip is non-nil, one additional A
// record mapping hostName to ip. Names are written uncompressed except the
// PTR answer's owner, which compresses against the PTR question.
func mdnsResponse(instance, hostName string, ip net.IP) []byte {
	msg := make([]byte, dnsHeaderLen)
	binary.BigEndian.PutUint16(msg[2:4], 0x8400) // standard response, authoritative

	question := encodeName("_airplay._tcp.local")
	binary.BigEndian.PutUint16(msg[4:6], 1)
	msg = append(msg, question...)
	msg = binary.BigEndian.AppendUint16(msg, dnsTypePTR)
	msg = binary.BigEndian.AppendUint16(msg, dnsClassIN)

	// PTR answer: owner name via compression pointer to the question.
	binary.BigEndian.PutUint16(msg[6:8], 1)
	msg = append(msg, 0xC0, byte(dnsHeaderLen))
	msg = binary.BigEndian.AppendUint16(msg, dnsTypePTR)
	msg = binary.BigEndian.AppendUint16(msg, dnsClassIN)
	msg = binary.BigEndian.AppendUint32(msg, 120)
	target := encodeName(instance)
	msg = binary.BigEndian.AppendUint16(msg, uint16(len(target)))
	msg = append(msg, target...)

	if ip != nil {
		binary.BigEndian.PutUint16(msg[10:12], 1)
		msg = append(msg, encodeName(hostName)...)
		msg = binary.BigEndian.AppendUint16(msg, dnsTypeA)
		msg = binary.BigEndian.AppendUint16(msg, dnsClassIN)
		msg = binary.BigEndian.AppendUint32(msg, 120)
		msg = binary.BigEndian.AppendUint16(msg, 4)
		msg = append(msg, ip.To4()...)
	}
	return msg
}

func TestParseMDNSMessage(t *testing.T) {
	valid := mdnsResponse("Living-Room-TV._airplay._tcp.local", "Living-Room-TV.local", net.IPv4(192, 168, 1, 50))

	truncatedRData := mdnsResponse("x._ssh._tcp.local", "x.local", net.IPv4(10, 0, 0, 1))
	truncatedRData = truncatedRData[:len(truncatedRData)-2]

	// A bare query (counts zeroed, no records) parses fine with no findings.
	questionOnly := make([]byte, dnsHeaderLen)

	tests := []struct {
		name    string
		msg     []byte
		wantErr bool
		check   func(t *testing.T, m mdnsMessage)
	}{
		{
			name: "valid response with compression",
			msg:  valid,
			check: func(t *testing.T, m mdnsMessage) {
				if len(m.ptrTargets) != 1 || m.ptrTargets[0] != "Living-Room-TV._airplay._tcp.local" {
					t.Errorf("ptrTargets = %v", m.ptrTargets)
				}
				ips := m.addrs["Living-Room-TV.local"]
				if len(ips) != 1 || ips[0] != "192.168.1.50" {
					t.Errorf("addrs = %v", m.addrs)
				}
			},
		},
		{name: "empty", msg: nil, wantErr: true},
		{name: "truncated header", msg: valid[:8], wantErr: true},
		{name: "truncated rdata", msg: truncatedRData, wantErr: true},
		{name: "garbage", msg: []byte{0xde, 0xad, 0xbe, 0xef, 0, 1, 2, 3, 4, 5, 6, 7}, wantErr: true},
		{
			name: "no records",
			msg:  questionOnly,
			check: func(t *testing.T, m mdnsMessage) {
				if len(m.ptrTargets) != 0 || len(m.addrs) != 0 {
					t.Errorf("expected no findings, got %+v", m)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m, err := parseMDNSMessage(tt.msg)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			tt.check(t, m)
		})
	}
}

func TestParseMDNSMessageAAAA(t *testing.T) {
	msg := make([]byte, dnsHeaderLen)
	binary.BigEndian.PutUint16(msg[2:4], 0x8400)
	binary.BigEndian.PutUint16(msg[6:8], 1)
	msg = append(msg, encodeName("nas.local")...)
	msg = binary.BigEndian.AppendUint16(msg, dnsTypeAAAA)
	msg = binary.BigEndian.AppendUint16(msg, dnsClassIN)
	msg = binary.BigEndian.AppendUint32(msg, 120)
	msg = binary.BigEndian.AppendUint16(msg, 16)
	msg = append(msg, net.ParseIP("fe80::1").To16()...)

	m, err := parseMDNSMessage(msg)
	if err != nil {
		t.Fatal(err)
	}
	if ips := m.addrs["nas.local"]; len(ips) != 1 || ips[0] != "fe80::1" {
		t.Errorf("addrs = %v, want fe80::1 for nas.local", m.addrs)
	}
}

func TestCleanMDNSName(t *testing.T) {
	tests := []struct {
		in   string
		want string
	}{
		{"Living-Room-TV._airplay._tcp.local.", "Living-Room-TV"},
		{"Living-Room-TV.local.", "Living-Room-TV"},
		{"Living-Room-TV.local", "Living-Room-TV"},
		{"Living-Room-TV", "Living-Room-TV"},
		{"My Printer._ipp._tcp.local.", "My Printer"},
		{"_ssh._tcp.local.", ""},
		{"_services._dns-sd._udp.local.", ""},
		{"", ""},
		{"  spaced.local.  ", "spaced"},
	}
	for _, tt := range tests {
		if got := cleanMDNSName(tt.in); got != tt.want {
			t.Errorf("cleanMDNSName(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestAbsorbMDNSPacket(t *testing.T) {
	t.Run("A record wins and is cleaned", func(t *testing.T) {
		results := make(map[string]string)
		src := &net.UDPAddr{IP: net.IPv4(192, 168, 1, 50), Port: 5353}
		absorbMDNSPacket(results, src, mdnsResponse(
			"Living-Room-TV._airplay._tcp.local", "Living-Room-TV.local", net.IPv4(192, 168, 1, 50)))
		assertMap(t, results, map[string]string{"192.168.1.50": "Living-Room-TV"})
	})

	// A PTR target names a service, not the host that sent the datagram. A
	// packet carrying no address record identifies nobody, and guessing the
	// sender mislabels every gateway and AP that relays mDNS between segments —
	// on a real network that named a UniFi gateway "Canon MF460 Series".
	t.Run("PTR target alone identifies nobody", func(t *testing.T) {
		results := make(map[string]string)
		src := &net.UDPAddr{IP: net.IPv4(192, 168, 1, 60), Port: 5353}
		absorbMDNSPacket(results, src, mdnsResponse("Office-Printer._ipp._tcp.local", "", nil))
		assertMap(t, results, map[string]string{})
	})

	// The relay case stated directly: an announcement forwarded by a router
	// asserts an address of its own, and that address is what must be labelled.
	t.Run("relayed announcement labels the subject not the relay", func(t *testing.T) {
		results := make(map[string]string)
		relay := &net.UDPAddr{IP: net.IPv4(192, 168, 2, 1), Port: 5353}
		absorbMDNSPacket(results, relay, mdnsResponse(
			"Canon-MF460._ipp._tcp.local", "Canon-MF460.local", net.IPv4(192, 168, 0, 241)))
		assertMap(t, results, map[string]string{"192.168.0.241": "Canon-MF460"})
	})

	t.Run("malformed packet ignored", func(t *testing.T) {
		results := map[string]string{"10.0.0.1": "existing"}
		absorbMDNSPacket(results, &net.UDPAddr{IP: net.IPv4(10, 0, 0, 2)}, []byte{1, 2, 3})
		assertMap(t, results, map[string]string{"10.0.0.1": "existing"})
	})

	t.Run("first name wins", func(t *testing.T) {
		results := make(map[string]string)
		src := &net.UDPAddr{IP: net.IPv4(192, 168, 1, 50), Port: 5353}
		absorbMDNSPacket(results, src, mdnsResponse(
			"Living-Room-TV._airplay._tcp.local", "Living-Room-TV.local", net.IPv4(192, 168, 1, 50)))
		absorbMDNSPacket(results, src, mdnsResponse(
			"Renamed._airplay._tcp.local", "Renamed.local", net.IPv4(192, 168, 1, 50)))
		assertMap(t, results, map[string]string{"192.168.1.50": "Living-Room-TV"})
	})
}

// loopbackPair returns a discovery socket and a responder socket on loopback,
// so discovery can be exercised end to end without multicast or a real LAN.
func loopbackPair(t *testing.T) (disc, resp *net.UDPConn) {
	t.Helper()
	var err error
	disc, err = net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("discovery socket: %v", err)
	}
	t.Cleanup(func() { disc.Close() })
	resp, err = net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("responder socket: %v", err)
	}
	t.Cleanup(func() { resp.Close() })
	return disc, resp
}

func TestRunMDNSNoResponders(t *testing.T) {
	disc, resp := loopbackPair(t)
	// The responder socket is bound but never answers.

	start := time.Now()
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	results := runMDNS(ctx, MDNSConfig{ServiceTypes: []string{"_ssh._tcp.local"}}, disc,
		resp.LocalAddr().(*net.UDPAddr))

	if len(results) != 0 {
		t.Errorf("expected empty results, got %v", results)
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Errorf("took %v, want a quick return on a silent network", elapsed)
	}
}

func TestRunMDNSFakeResponder(t *testing.T) {
	disc, resp := loopbackPair(t)

	go func() {
		buf := make([]byte, 65535)
		n, src, err := resp.ReadFromUDP(buf)
		if err != nil {
			return
		}
		if _, err := parseMDNSMessage(buf[:n]); err != nil {
			return // not a well-formed query; nothing to answer
		}
		_, _ = resp.WriteToUDP(mdnsResponse(
			"Fake-TV._airplay._tcp.local", "Fake-TV.local", net.IPv4(127, 0, 0, 1)), src)
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	results := runMDNS(ctx, MDNSConfig{ServiceTypes: []string{"_airplay._tcp.local"}}, disc,
		resp.LocalAddr().(*net.UDPAddr))
	assertMap(t, results, map[string]string{"127.0.0.1": "Fake-TV"})
}

func TestLookupMDNSReturnsFast(t *testing.T) {
	start := time.Now()
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	results := LookupMDNS(ctx, MDNSConfig{})
	if results == nil {
		t.Error("expected non-nil map even when discovery is impossible")
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Errorf("took %v, want bounded execution", elapsed)
	}
}
