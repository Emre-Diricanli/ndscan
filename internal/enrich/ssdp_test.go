package enrich

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"
)

func TestBuildMSearch(t *testing.T) {
	msg := string(buildMSearch("ssdp:all", 1))
	for _, want := range []string{
		"M-SEARCH * HTTP/1.1\r\n",
		"HOST: 239.255.255.250:1900\r\n",
		"MAN: \"ssdp:discover\"\r\n",
		"MX: 1\r\n",
		"ST: ssdp:all\r\n",
	} {
		if !strings.Contains(msg, want) {
			t.Errorf("M-SEARCH missing %q:\n%s", want, msg)
		}
	}
	if !strings.HasSuffix(msg, "\r\n\r\n") {
		t.Error("M-SEARCH must end with a blank line")
	}
}

func TestParseSSDPHeaders(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want map[string]string
	}{
		{
			name: "canonical CRLF response",
			in: "HTTP/1.1 200 OK\r\n" +
				"CACHE-CONTROL: max-age=1800\r\n" +
				"SERVER: Linux/4.4 UPnP/1.0 MyDevice/2.1\r\n" +
				"USN: uuid:abc-123::upnp:rootdevice\r\n" +
				"\r\n",
			want: map[string]string{
				"cache-control": "max-age=1800",
				"server":        "Linux/4.4 UPnP/1.0 MyDevice/2.1",
				"usn":           "uuid:abc-123::upnp:rootdevice",
			},
		},
		{
			name: "bare LF and sloppy spacing",
			in:   "HTTP/1.1 200 OK\nServer:  some-device/1.0 \nUSN :uuid:x::ssdp:all\n",
			want: map[string]string{
				"server": "some-device/1.0",
				"usn":    "uuid:x::ssdp:all",
			},
		},
		{
			name: "junk lines skipped",
			in:   "HTTP/1.1 200 OK\r\nnot-a-header\r\nST: upnp:rootdevice\r\n",
			want: map[string]string{"st": "upnp:rootdevice"},
		},
		{name: "empty", in: "", want: map[string]string{}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseSSDPHeaders([]byte(tt.in))
			if len(got) != len(tt.want) {
				t.Fatalf("got %v, want %v", got, tt.want)
			}
			for k, v := range tt.want {
				if got[k] != v {
					t.Errorf("header %q = %q, want %q", k, got[k], v)
				}
			}
		})
	}
}

func TestSSDPLabel(t *testing.T) {
	tests := []struct {
		name    string
		headers map[string]string
		want    string
	}{
		{
			name:    "server without boilerplate",
			headers: map[string]string{"server": "Linux/4.4 UPnP/1.0 MyDevice/2.1"},
			want:    "Linux/4.4 MyDevice/2.1",
		},
		{
			name:    "DLNADOC token dropped",
			headers: map[string]string{"server": "UPnP/1.0 DLNADOC/1.50 Samsung-TV/3.0"},
			want:    "Samsung-TV/3.0",
		},
		{
			name:    "server only boilerplate falls back to USN",
			headers: map[string]string{"server": "UPnP/1.0 DLNADOC/1.50", "usn": "uuid:abc-123::upnp:rootdevice"},
			want:    "abc-123",
		},
		{
			name:    "usn suffix stripped",
			headers: map[string]string{"usn": "uuid:xyz-789::urn:schemas-upnp-org:device:MediaRenderer:1"},
			want:    "xyz-789",
		},
		{name: "nothing useful", headers: map[string]string{"st": "ssdp:all"}, want: ""},
		{name: "empty", headers: map[string]string{}, want: ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ssdpLabel(tt.headers); got != tt.want {
				t.Errorf("ssdpLabel(%v) = %q, want %q", tt.headers, got, tt.want)
			}
		})
	}
}

func TestAbsorbSSDPPacket(t *testing.T) {
	t.Run("labeled response", func(t *testing.T) {
		results := make(map[string]string)
		src := &net.UDPAddr{IP: net.IPv4(192, 168, 1, 70), Port: 1900}
		resp := "HTTP/1.1 200 OK\r\nSERVER: RouterOS/7.1 UPnP/1.0 MikroTik/1.0\r\n\r\n"
		absorbSSDPPacket(results, src, []byte(resp))
		assertMap(t, results, map[string]string{"192.168.1.70": "RouterOS/7.1 MikroTik/1.0"})
	})

	t.Run("label-less response yields no entry", func(t *testing.T) {
		results := make(map[string]string)
		src := &net.UDPAddr{IP: net.IPv4(192, 168, 1, 71), Port: 1900}
		absorbSSDPPacket(results, src, []byte("HTTP/1.1 200 OK\r\nST: ssdp:all\r\n\r\n"))
		assertMap(t, results, map[string]string{})
	})

	t.Run("first label wins", func(t *testing.T) {
		results := make(map[string]string)
		src := &net.UDPAddr{IP: net.IPv4(192, 168, 1, 72), Port: 1900}
		absorbSSDPPacket(results, src, []byte("HTTP/1.1 200 OK\r\nSERVER: first/1.0\r\n\r\n"))
		absorbSSDPPacket(results, src, []byte("HTTP/1.1 200 OK\r\nSERVER: second/2.0\r\n\r\n"))
		assertMap(t, results, map[string]string{"192.168.1.72": "first/1.0"})
	})
}

func TestCollectSSDPNoResponders(t *testing.T) {
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer conn.Close()

	start := time.Now()
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	results := make(map[string]string)
	readUntil(ctx, conn, func(src *net.UDPAddr, b []byte) {
		absorbSSDPPacket(results, src, b)
	})

	if len(results) != 0 {
		t.Errorf("expected empty results, got %v", results)
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Errorf("took %v, want a quick return on a silent network", elapsed)
	}
}

func TestCollectSSDPFakeResponder(t *testing.T) {
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer conn.Close()

	responder, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("responder: %v", err)
	}
	defer responder.Close()

	go func() {
		resp := "HTTP/1.1 200 OK\r\n" +
			"SERVER: FakeOS/1.0 UPnP/1.0 FakeSpeaker/4.2\r\n" +
			"USN: uuid:deadbeef::upnp:rootdevice\r\n\r\n"
		_, _ = responder.WriteToUDP([]byte(resp), conn.LocalAddr().(*net.UDPAddr))
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	results := make(map[string]string)
	readUntil(ctx, conn, func(src *net.UDPAddr, b []byte) {
		absorbSSDPPacket(results, src, b)
		if len(results) > 0 {
			cancel() // got what we came for; no need to sit out the deadline
		}
	})
	assertMap(t, results, map[string]string{"127.0.0.1": "FakeOS/1.0 FakeSpeaker/4.2"})
}

func TestLookupSSDPReturnsFast(t *testing.T) {
	start := time.Now()
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	results := LookupSSDP(ctx, SSDPConfig{})
	if results == nil {
		t.Error("expected non-nil map even when discovery is impossible")
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Errorf("took %v, want bounded execution", elapsed)
	}
}
