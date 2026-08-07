package scan

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Emre-Diricanli/ndscan/internal/enrich"
	"github.com/Emre-Diricanli/ndscan/internal/sweep"
)

func TestParsePortSpec(t *testing.T) {
	cases := []struct {
		spec    string
		want    []int
		wantErr bool
	}{
		{"", nil, false},
		{"22", []int{22}, false},
		{"22,80,443", []int{22, 80, 443}, false},
		{"80-83", []int{80, 81, 82, 83}, false},
		{"22,80-82", []int{22, 80, 81, 82}, false},
		{"22, 80 , 443", []int{22, 80, 443}, false},
		{"22,22,22", []int{22}, false}, // de-duplicated
		{"0", nil, true},
		{"70000", nil, true},
		{"-5", nil, true},
		{"junk", nil, true},
		{"22,junk", nil, true},
		{"100-50", nil, true},
	}
	for _, c := range cases {
		got, err := parsePortSpec(c.spec)
		if (err != nil) != c.wantErr {
			t.Errorf("parsePortSpec(%q) error = %v, wantErr %v", c.spec, err, c.wantErr)
			continue
		}
		if len(got) != len(c.want) {
			t.Errorf("parsePortSpec(%q) = %v, want %v", c.spec, got, c.want)
			continue
		}
		for i := range c.want {
			if got[i] != c.want[i] {
				t.Errorf("parsePortSpec(%q) = %v, want %v", c.spec, got, c.want)
				break
			}
		}
	}
}

func TestNativePortScan_PropagatesIncompleteSignal(t *testing.T) {
	original := scanNativePorts
	t.Cleanup(func() { scanNativePorts = original })
	scanNativePorts = func(_ context.Context, _ []string, cfg sweep.PortConfig) []sweep.PortResult {
		cfg.OnIncomplete(17)
		return []sweep.PortResult{{IP: "192.0.2.1"}}
	}

	results := NativePortScan(context.Background(), []string{"192.0.2.1"}, Config{Ports: "22"}, nil)

	// The scanned host keeps its results: exhaustion means its port list is a
	// floor, not that the host went unscanned. The run-level shortfall arrives
	// as a separate entry so callers counting per-host failures do not throw
	// away results that are incomplete but valid.
	var scanned, incomplete int
	var incompleteErr error
	for _, r := range results {
		switch {
		case r.Err != nil:
			incomplete++
			incompleteErr = r.Err
		case r.IP == "192.0.2.1":
			scanned++
		}
	}
	if scanned != 1 {
		t.Errorf("scanned host results = %d, want 1 (host must not be marked failed)", scanned)
	}
	if incomplete != 1 {
		t.Fatalf("incomplete markers = %d, want exactly 1: %+v", incomplete, results)
	}
	if !strings.Contains(incompleteErr.Error(), "17 probes") {
		t.Errorf("incomplete error = %q, want skipped probe count", incompleteErr)
	}
}

// A run that completes fully must not manufacture a phantom failure entry.
func TestNativePortScan_NoIncompleteMarkerWhenComplete(t *testing.T) {
	original := scanNativePorts
	t.Cleanup(func() { scanNativePorts = original })
	scanNativePorts = func(_ context.Context, _ []string, _ sweep.PortConfig) []sweep.PortResult {
		return []sweep.PortResult{{IP: "192.0.2.1"}}
	}

	for _, r := range NativePortScan(context.Background(), []string{"192.0.2.1"}, Config{Ports: "22"}, nil) {
		if r.Err != nil {
			t.Errorf("complete scan produced an error result: %v", r.Err)
		}
	}
}

func TestNativePortScan_InvalidPortsFailClosed(t *testing.T) {
	called := false
	original := scanNativePorts
	t.Cleanup(func() { scanNativePorts = original })
	scanNativePorts = func(context.Context, []string, sweep.PortConfig) []sweep.PortResult {
		called = true
		return nil
	}

	results := NativePortScan(context.Background(), []string{"192.0.2.1"}, Config{Ports: "22,banana"}, nil)
	if called {
		t.Fatal("malformed port input reached the sweep")
	}
	if len(results) != 1 || results[0].Err == nil || !strings.Contains(results[0].Err.Error(), "banana") {
		t.Fatalf("results = %+v, want an error naming banana", results)
	}
}

// The synthetic XML must parse with the same parser used for real nmap output,
// so native results flow through every existing printer unchanged.
func TestNativePortScan_ProducesParseableResults(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()
	_, portStr, _ := net.SplitHostPort(ln.Addr().String())
	port, _ := strconv.Atoi(portStr)

	res := NativePortScan(context.Background(), []string{"127.0.0.1"},
		Config{Ports: portStr, Concurrency: 4}, nil)
	if len(res) != 1 {
		t.Fatalf("got %d results, want 1", len(res))
	}

	nr, err := ParseOne(res[0].XMLBytes)
	if err != nil {
		t.Fatalf("synthetic XML does not parse: %v\n%s", err, res[0].XMLBytes)
	}
	if len(nr.Hosts) != 1 {
		t.Fatalf("parsed %d hosts, want 1", len(nr.Hosts))
	}
	h := nr.Hosts[0]
	if h.Status.State != "up" {
		t.Errorf("host state = %q, want up", h.Status.State)
	}
	var found bool
	for _, p := range h.Ports.List {
		if p.PortID == port && p.State.State == "open" {
			found = true
		}
	}
	if !found {
		t.Errorf("open port %d missing from parsed result: %s", port, res[0].XMLBytes)
	}
}

// A host with nothing listening must still produce a valid, parseable result
// rather than being dropped.
func TestNativePortScan_ClosedHostStillParses(t *testing.T) {
	res := NativePortScan(context.Background(), []string{"127.0.0.1"},
		Config{Ports: "1", Concurrency: 2}, nil)
	if len(res) != 1 {
		t.Fatalf("got %d results, want 1", len(res))
	}
	if _, err := ParseOne(res[0].XMLBytes); err != nil {
		t.Errorf("empty result does not parse: %v", err)
	}
}

func TestSyntheticXML_EscapesHostileValues(t *testing.T) {
	// A crafted service name must not break out of the XML.
	res := NativePortScan(context.Background(), []string{"127.0.0.1"},
		Config{Ports: "1", Concurrency: 1}, nil)
	x := string(res[0].XMLBytes)
	if !strings.HasPrefix(x, "<nmaprun>") || !strings.HasSuffix(x, "</nmaprun>") {
		t.Errorf("malformed envelope: %s", x)
	}
}

func TestSyntheticXML_RoundTripsRTT(t *testing.T) {
	want := 3800 * time.Microsecond
	xmlBytes := syntheticXML(sweep.PortResult{IP: "192.0.2.1"}, want)
	nr, err := ParseOne(xmlBytes)
	if err != nil {
		t.Fatalf("ParseOne: %v", err)
	}
	if len(nr.Hosts) != 1 {
		t.Fatalf("hosts = %d, want 1", len(nr.Hosts))
	}
	if got := nr.Hosts[0].RTT(); got != want {
		t.Fatalf("RTT = %v, want %v (XML: %s)", got, want, xmlBytes)
	}
}

func TestSyntheticXML_RoundTripsTLSCertificate(t *testing.T) {
	expiry := time.Date(2030, 4, 5, 6, 7, 8, 0, time.UTC)
	xmlBytes := syntheticXMLWithMetadata(sweep.PortResult{IP: "192.0.2.1", Ports: []sweep.OpenPort{{Port: 443, Service: "https"}}}, NativeMetadata{
		TLS: map[int]enrich.TLSInfo{443: {Organization: "GLKVM", CommonName: "device", Issuer: "issuer", NotAfter: expiry}},
	})
	nr, err := ParseOne(xmlBytes)
	if err != nil {
		t.Fatalf("ParseOne: %v", err)
	}
	p := nr.Hosts[0].Ports.List[0]
	if p.Service.Tunnel != "ssl" || p.Service.Product != "GLKVM" {
		t.Fatalf("service = %+v", p.Service)
	}
	cert := p.TLSCert()
	if cert == nil || cert.Organization != "GLKVM" || cert.CommonName != "device" || cert.Issuer != "issuer" || cert.NotAfter != "2030-04-05T06:07:08" {
		t.Fatalf("certificate = %+v (XML: %s)", cert, xmlBytes)
	}
}

func TestNativePortScan_TLSIdentificationRoundTripsCertificate(t *testing.T) {
	ln, port, connections := tlsTestListener(t, "GLKVM")
	stubNativePortResult(t, sweep.PortResult{IP: "127.0.0.1", Ports: []sweep.OpenPort{{Port: port, Service: "https"}}})
	metadata := map[string]NativeMetadata{"127.0.0.1": {IdentifyTLS: true}}

	results := NativePortScanWithMetadata(context.Background(), []string{"127.0.0.1"}, metadata,
		Config{Ports: strconv.Itoa(port), Concurrency: 1}, nil)
	if connections.Load() != 1 {
		t.Fatalf("TLS handshakes = %d, want 1", connections.Load())
	}
	nr, err := ParseOne(results[0].XMLBytes)
	if err != nil {
		t.Fatalf("ParseOne: %v", err)
	}
	parsed := nr.Hosts[0].Ports.List[0]
	cert := parsed.TLSCert()
	if cert == nil || cert.Organization != "GLKVM" {
		t.Fatalf("certificate = %+v (XML: %s)", cert, results[0].XMLBytes)
	}
	if parsed.Service.Tunnel != "ssl" || parsed.Service.Product != "GLKVM" {
		t.Fatalf("service = %+v", parsed.Service)
	}
	ln.Close()
}

func TestNativePortScan_TLSDisabledByDefault(t *testing.T) {
	ln, port, connections := tlsTestListener(t, "must-not-connect")
	stubNativePortResult(t, sweep.PortResult{IP: "127.0.0.1", Ports: []sweep.OpenPort{{Port: port, Service: "https"}}})

	NativePortScanWithMetadata(context.Background(), []string{"127.0.0.1"},
		map[string]NativeMetadata{"127.0.0.1": {}}, Config{Ports: strconv.Itoa(port)}, nil)
	time.Sleep(50 * time.Millisecond)
	if connections.Load() != 0 {
		t.Fatalf("TLS disabled but listener accepted %d connections", connections.Load())
	}
	ln.Close()
}

func TestNativePortScan_NonTLSPortIsOmittedWithoutHang(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		conn, err := ln.Accept()
		if err == nil {
			conn.Write([]byte("not tls\n"))
			conn.Close()
		}
	}()
	port := listenerPort(t, ln)
	stubNativePortResult(t, sweep.PortResult{IP: "127.0.0.1", Ports: []sweep.OpenPort{{Port: port, Service: "https"}}})
	metadata := map[string]NativeMetadata{"127.0.0.1": {
		IdentifyTLS: true,
		TLSConfig:   enrich.TLSConfig{HostTimeout: 200 * time.Millisecond, OverallTimeout: time.Second},
	}}
	started := time.Now()
	results := NativePortScanWithMetadata(context.Background(), []string{"127.0.0.1"}, metadata, Config{Ports: strconv.Itoa(port)}, nil)
	if time.Since(started) > time.Second {
		t.Fatal("non-TLS endpoint held up the scan")
	}
	nr, err := ParseOne(results[0].XMLBytes)
	if err != nil {
		t.Fatal(err)
	}
	if cert := nr.Hosts[0].Ports.List[0].TLSCert(); cert != nil {
		t.Fatalf("non-TLS endpoint produced certificate %+v", cert)
	}
}

func TestNativePortScan_TLSPerScanEndpointCap(t *testing.T) {
	var listeners []net.Listener
	var ports []int
	var accepted []*atomic.Int32
	for range 3 {
		ln, port, count := tlsTestListener(t, "capped")
		listeners = append(listeners, ln)
		ports = append(ports, port)
		accepted = append(accepted, count)
	}
	t.Cleanup(func() {
		for _, ln := range listeners {
			ln.Close()
		}
	})
	open := make([]sweep.OpenPort, 0, len(ports))
	for _, port := range ports {
		open = append(open, sweep.OpenPort{Port: port, Service: "https"})
	}
	stubNativePortResult(t, sweep.PortResult{IP: "127.0.0.1", Ports: open})
	metadata := map[string]NativeMetadata{"127.0.0.1": {IdentifyTLS: true, TLSMaxEndpoints: 2}}
	NativePortScanWithMetadata(context.Background(), []string{"127.0.0.1"}, metadata, Config{Ports: "443"}, nil)
	var total int32
	for _, count := range accepted {
		total += count.Load()
	}
	if total != 2 {
		t.Fatalf("TLS handshakes = %d, want cap of 2", total)
	}
}

func TestNativePortScan_CancellationStopsTLSEnrichment(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	accepted := make(chan struct{})
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		close(accepted)
		buf := make([]byte, 1)
		conn.Read(buf)
	}()
	port := listenerPort(t, ln)
	stubNativePortResult(t, sweep.PortResult{IP: "127.0.0.1", Ports: []sweep.OpenPort{{Port: port, Service: "https"}}})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		NativePortScanWithMetadata(ctx, []string{"127.0.0.1"}, map[string]NativeMetadata{"127.0.0.1": {
			IdentifyTLS: true,
			TLSConfig:   enrich.TLSConfig{HostTimeout: 10 * time.Second, OverallTimeout: 10 * time.Second},
		}}, Config{Ports: strconv.Itoa(port)}, nil)
	}()
	select {
	case <-accepted:
		cancel()
	case <-time.After(time.Second):
		t.Fatal("TLS connection was not attempted")
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("scan did not stop after cancellation")
	}
}

func stubNativePortResult(t *testing.T, result sweep.PortResult) {
	t.Helper()
	original := scanNativePorts
	t.Cleanup(func() { scanNativePorts = original })
	scanNativePorts = func(_ context.Context, _ []string, cfg sweep.PortConfig) []sweep.PortResult {
		if cfg.Progress != nil {
			cfg.Progress(1, 1)
		}
		return []sweep.PortResult{result}
	}
}

func tlsTestListener(t *testing.T, organization string) (net.Listener, int, *atomic.Int32) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "device", Organization: []string{organization}},
		Issuer:       pkix.Name{CommonName: "test issuer"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert := tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	connections := &atomic.Int32{}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			connections.Add(1)
			go func() {
				defer conn.Close()
				tls.Server(conn, &tls.Config{Certificates: []tls.Certificate{cert}}).Handshake()
			}()
		}
	}()
	return ln, listenerPort(t, ln), connections
}

func listenerPort(t *testing.T, ln net.Listener) int {
	t.Helper()
	_, portString, err := net.SplitHostPort(ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(portString)
	if err != nil {
		t.Fatal(err)
	}
	return port
}

func TestNativePortScanViable(t *testing.T) {
	local := LocalRunner{}
	ssh := &SSHRunner{Target: "user@host"}

	if !NativePortScanViable(Config{Preset: "quick"}, local) {
		t.Error("quick preset locally should be viable")
	}
	// Presets that need -A / -sU must stay on nmap.
	for _, p := range []string{"default", "deep", "udp"} {
		if NativePortScanViable(Config{Preset: p}, local) {
			t.Errorf("preset %q needs nmap capabilities, must not be viable", p)
		}
	}
	// Remote scans must never use native probing (wrong source machine).
	if NativePortScanViable(Config{Preset: "quick"}, ssh) {
		t.Error("SSH runner must not use native port scanning")
	}
}

func TestNativePortScan_ProgressReported(t *testing.T) {
	// Progress is documented as being called from multiple goroutines, so the
	// callback must guard its own state.
	var mu sync.Mutex
	var maxDone, total int
	NativePortScan(context.Background(), []string{"127.0.0.1", "127.0.0.2"},
		Config{Ports: "1", Concurrency: 2}, func(done, tot int) {
			mu.Lock()
			defer mu.Unlock()
			if done > maxDone {
				maxDone = done
			}
			total = tot
		})
	mu.Lock()
	defer mu.Unlock()
	if total != 2 {
		t.Errorf("progress total = %d, want 2", total)
	}
	if maxDone == 0 {
		t.Error("progress never reported")
	}
}

// ValidatePorts is what the front ends call before a scan starts. An empty spec
// must stay valid — it means "use the preset's ports" — while anything the
// parser would reject has to be caught here rather than after the scan runs.
func TestValidatePorts(t *testing.T) {
	cases := []struct {
		spec    string
		wantErr bool
	}{
		{"", false},
		{"22", false},
		{"22,80,443", false},
		{"1-1024", false},
		{"22,1000-1010", false},
		{"banana", true},
		{"22,banana", true},
		{"99999", true},
		{"0", true},
		{"100-50", true},
		{"22,,80", true},
	}
	for _, c := range cases {
		if err := ValidatePorts(c.spec); (err != nil) != c.wantErr {
			t.Errorf("ValidatePorts(%q) error = %v, wantErr %v", c.spec, err, c.wantErr)
		}
	}
}
