package enrich

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"testing"
	"time"
)

func TestProbeTLSExtractsAndSanitizesCertificate(t *testing.T) {
	expiry := time.Date(2030, 4, 5, 6, 7, 8, 0, time.UTC)
	ln := newTLSListener(t, pkix.Name{
		CommonName:   "device\x1b[2J-name",
		Organization: []string{"GLKVM"},
	}, pkix.Name{CommonName: "Test Issuer"}, expiry)
	defer ln.Close()
	serveConnections(ln)
	endpoint := ln.Addr().String()

	got := LookupTLS(context.Background(), []string{endpoint}, TLSConfig{Workers: 1})
	info, ok := got[endpoint]
	if !ok {
		t.Fatal("TLS endpoint returned no certificate result")
	}
	if info.Organization != "GLKVM" || info.CommonName != "device-name" || info.Issuer != "Test Issuer" {
		t.Fatalf("certificate identity = %+v", info)
	}
	if !info.NotAfter.Equal(expiry) {
		t.Fatalf("expiry = %v, want %v", info.NotAfter, expiry)
	}
}

func TestProbeTLSMissesAreSilentAndTimeoutIsHonoured(t *testing.T) {
	plain, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer plain.Close()
	go func() {
		for {
			conn, err := plain.Accept()
			if err != nil {
				return
			}
			go func() { defer conn.Close(); <-time.After(time.Second) }()
		}
	}()

	closed, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	closedEndpoint := closed.Addr().String()
	closed.Close()
	plainEndpoint := plain.Addr().String()
	start := time.Now()
	got := LookupTLS(context.Background(), []string{plainEndpoint, closedEndpoint}, TLSConfig{
		Workers: 2, HostTimeout: 60 * time.Millisecond, OverallTimeout: 200 * time.Millisecond,
	})
	if len(got) != 0 {
		t.Fatalf("non-TLS/closed endpoints returned results: %+v", got)
	}
	if elapsed := time.Since(start); elapsed > 300*time.Millisecond {
		t.Fatalf("probe took %v, timeout was not honoured", elapsed)
	}
}

func newTLSListener(t *testing.T, subject, issuer pkix.Name, expiry time.Time) net.Listener {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: subject,
		NotBefore: time.Now().Add(-time.Hour), NotAfter: expiry,
		KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
	}
	parent := *template
	parent.Subject = issuer
	der, err := x509.CreateCertificate(rand.Reader, template, &parent, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert := tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}})
	if err != nil {
		t.Fatal(err)
	}
	return ln
}

func serveConnections(ln net.Listener) {
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				if tlsConn, ok := conn.(*tls.Conn); ok {
					_ = tlsConn.Handshake()
				}
			}()
		}
	}()
}
