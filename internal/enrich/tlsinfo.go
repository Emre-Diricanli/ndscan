package enrich

import (
	"context"
	"crypto/tls"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"
)

const (
	defaultTLSWorkers        = 16
	defaultTLSHostTimeout    = 500 * time.Millisecond
	defaultTLSOverallTimeout = 2 * time.Second
)

// TLSInfo is identification metadata from an open endpoint's leaf certificate.
// All strings are sanitized because certificates are controlled by the host.
type TLSInfo struct {
	Organization string
	CommonName   string
	Issuer       string
	NotAfter     time.Time
}

// TLSConfig bounds certificate identification. Endpoints must be host:port
// strings for ports the scanner already knows are open.
type TLSConfig struct {
	Workers          int
	HostTimeout      time.Duration
	HandshakeTimeout time.Duration
	OverallTimeout   time.Duration
}

// TLSEndpoint identifies one port already known to be open.
type TLSEndpoint struct {
	Host string
	Port int
}

func (e TLSEndpoint) address() string {
	return net.JoinHostPort(e.Host, strconv.Itoa(e.Port))
}

// ProbeTLS identifies certificates on structured open endpoints.
func ProbeTLS(ctx context.Context, endpoints []TLSEndpoint, cfg TLSConfig) map[TLSEndpoint]TLSInfo {
	addresses := make([]string, 0, len(endpoints))
	byAddress := make(map[string]TLSEndpoint, len(endpoints))
	for _, endpoint := range endpoints {
		address := endpoint.address()
		addresses = append(addresses, address)
		byAddress[address] = endpoint
	}
	identified := LookupTLS(ctx, addresses, cfg)
	results := make(map[TLSEndpoint]TLSInfo, len(identified))
	for address, info := range identified {
		results[byAddress[address]] = info
	}
	return results
}

// LookupTLS performs only TLS handshakes against the supplied open endpoints.
// It sends no application data, opens no additional ports, and silently omits
// endpoints which do not speak TLS. Results found before cancellation or the
// overall deadline are retained.
func LookupTLS(ctx context.Context, endpoints []string, cfg TLSConfig) map[string]TLSInfo {
	cfg = tlsDefaults(cfg)
	ctx, cancel := context.WithTimeout(ctx, cfg.OverallTimeout)
	defer cancel()

	results := make(map[string]TLSInfo)
	jobs := make(chan string)
	var mu sync.Mutex
	var workers sync.WaitGroup
	workers.Add(cfg.Workers)
	for range cfg.Workers {
		go func() {
			defer workers.Done()
			for endpoint := range jobs {
				probeCtx, probeCancel := context.WithTimeout(ctx, cfg.HostTimeout)
				info, ok := lookupOneTLS(probeCtx, endpoint)
				probeCancel()
				if ok {
					mu.Lock()
					results[endpoint] = info
					mu.Unlock()
				}
			}
		}()
	}

send:
	for _, endpoint := range endpoints {
		select {
		case jobs <- endpoint:
		case <-ctx.Done():
			break send
		}
	}
	close(jobs)
	workers.Wait()
	return results
}

func tlsDefaults(cfg TLSConfig) TLSConfig {
	if cfg.Workers <= 0 {
		cfg.Workers = defaultTLSWorkers
	}
	if cfg.HostTimeout <= 0 {
		cfg.HostTimeout = cfg.HandshakeTimeout
		if cfg.HostTimeout <= 0 {
			cfg.HostTimeout = defaultTLSHostTimeout
		}
	}
	if cfg.OverallTimeout <= 0 {
		cfg.OverallTimeout = defaultTLSOverallTimeout
	}
	return cfg
}

func lookupOneTLS(ctx context.Context, endpoint string) (TLSInfo, bool) {
	dialer := &net.Dialer{}
	conn, err := dialer.DialContext(ctx, "tcp", endpoint)
	if err != nil {
		return TLSInfo{}, false
	}
	defer conn.Close()

	host, _, err := net.SplitHostPort(endpoint)
	if err != nil {
		return TLSInfo{}, false
	}
	tlsCfg := &tls.Config{
		// This scan identifies a service; it does not authenticate or trust it.
		// LAN appliances commonly use self-signed or name-mismatched certs.
		InsecureSkipVerify: true, //nolint:gosec
	}
	if net.ParseIP(host) == nil {
		tlsCfg.ServerName = host
	}
	tlsConn := tls.Client(conn, tlsCfg)
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		return TLSInfo{}, false
	}
	certs := tlsConn.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		return TLSInfo{}, false
	}
	leaf := certs[0]
	return TLSInfo{
		Organization: cleanCertificateText(strings.Join(leaf.Subject.Organization, ", ")),
		CommonName:   cleanCertificateText(leaf.Subject.CommonName),
		Issuer:       cleanCertificateText(leaf.Issuer.CommonName),
		NotAfter:     leaf.NotAfter,
	}, true
}

// cleanCertificateText removes terminal control characters and complete ANSI
// escape sequences while preserving printable Unicode. This is the same
// attacker-controlled terminal-injection hazard handled by ui.stripControls;
// sanitizing here also protects non-UI callers of this package.
func cleanCertificateText(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	state := 0 // normal, after ESC, or inside CSI
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		switch state {
		case 1:
			if r == '[' {
				state = 2
			} else {
				state = 0
			}
		case 2:
			if r >= 0x40 && r <= 0x7e {
				state = 0
			}
		default:
			switch {
			case r == 0x1b:
				state = 1
			case r == 0x9b:
				state = 2
			case r == utf8.RuneError && size == 1:
				if s[i] == 0x9b {
					state = 2
				}
			case unicode.IsControl(r):
			default:
				b.WriteString(s[i : i+size])
			}
		}
		i += size
	}
	return b.String()
}
