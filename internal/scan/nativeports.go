package scan

import (
	"context"
	"encoding/xml"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/Emre-Diricanli/ndscan/internal/enrich"
	"github.com/Emre-Diricanli/ndscan/internal/sweep"
)

var scanNativePorts = sweep.ScanPorts

// NativePortScan probes open ports on the given hosts without invoking nmap,
// returning results in the same shape the nmap path produces so every existing
// parser, printer, and report renderer consumes them unchanged.
//
// It is dramatically faster than nmap for the common "what's open here" case,
// but it reports port numbers and well-known service names only — no version
// detection, OS fingerprinting, or NSE output. Callers needing those must use
// the nmap path (the deep/default presets).
//
// progress may be nil. When set it is called from multiple goroutines as hosts
// complete, so it must be safe for concurrent use.
//
// cfg.OnResult, when set, receives each host the instant it finishes probing
// rather than after every host has. Callers should prefer it over the returned
// slice: the slice can only be complete once the slowest unreachable address has
// burned its full timeout, whereas a responsive LAN host streams in
// milliseconds. The returned slice is still complete, for callers that only want
// the final answer.
func NativePortScan(ctx context.Context, hosts []string, cfg Config, progress func(done, total int)) []HostResult {
	return nativePortScan(ctx, hosts, nil, cfg, progress)
}

// NativeMetadata is enrichment to embed in one host's synthetic nmap XML.
type NativeMetadata struct {
	RTT time.Duration
	TLS map[int]enrich.TLSInfo
	// IdentifyTLS opts this scan into active TLS handshakes. It is deliberately
	// separate from TLS: callers may supply already-known certificate data
	// without authorizing network activity.
	IdentifyTLS bool
	// TLSConfig bounds the active identification work. Zero values use the
	// conservative defaults in enrich.LookupTLS.
	TLSConfig enrich.TLSConfig
	// TLSMaxEndpoints caps handshakes across the entire scan. Values <= 0 use
	// the package default. The first metadata entry with IdentifyTLS set owns
	// these scan-wide settings.
	TLSMaxEndpoints int
}

const defaultTLSMaxEndpoints = 64

// NativePortScanWithMetadata preserves discovery timing and TLS identification
// through the native scan's existing XML/parser/rendering path.
//
// The engine supplies the metadata: the discovery sweep already timed each
// host's answer, and passing that through here is what puts a value in the RTT
// column on the fast path. Setting IdentifyTLS on one metadata entry opts the
// run into bounded certificate identification after every open port is known.
func NativePortScanWithMetadata(ctx context.Context, hosts []string, metadata map[string]NativeMetadata, cfg Config, progress func(done, total int)) []HostResult {
	return nativePortScan(ctx, hosts, metadata, cfg, progress)
}

func nativePortScan(ctx context.Context, hosts []string, metadata map[string]NativeMetadata, cfg Config, progress func(done, total int)) []HostResult {
	ports, err := parsePortSpec(cfg.Ports)
	if err != nil {
		out := make([]HostResult, 0, len(hosts))
		for i, host := range hosts {
			result := HostResult{IP: host, Err: err}
			out = append(out, result)
			if cfg.OnResult != nil {
				cfg.OnResult(result)
			}
			if progress != nil {
				progress(i+1, len(hosts))
			}
		}
		return out
	}

	tlsCfg, tlsLimit, identifyTLS := nativeTLSSettings(hosts, metadata)
	var onResult func(sweep.PortResult)
	if cfg.OnResult != nil && !identifyTLS {
		onResult = func(r sweep.PortResult) {
			cfg.OnResult(HostResult{IP: r.IP, XMLBytes: syntheticXMLWithMetadata(r, metadata[r.IP])})
		}
	}

	var incomplete atomic.Int64
	results := scanNativePorts(ctx, hosts, sweep.PortConfig{
		Ports:       ports,
		Concurrency: cfg.Concurrency * 32, // per-host workers -> per-probe workers
		Progress:    progress,
		OnResult:    onResult,
		OnIncomplete: func(probes int) {
			incomplete.Store(int64(probes))
		},
	})

	if identifyTLS && ctx.Err() == nil {
		enrichNativeTLS(ctx, results, metadata, tlsCfg, tlsLimit)
	}

	out := make([]HostResult, 0, len(results))
	for _, r := range results {
		result := HostResult{
			IP:       r.IP,
			XMLBytes: syntheticXMLWithMetadata(r, metadata[r.IP]),
		}
		out = append(out, result)
		if cfg.OnResult != nil && identifyTLS {
			cfg.OnResult(result)
		}
	}
	// Descriptor exhaustion is a property of the run, not of any one host: every
	// host's ports are a floor rather than a full answer. Marking each result as
	// failed would say something different and worse — that those hosts were not
	// scanned at all — and callers that count failures would then discard a set
	// of results that is incomplete but still entirely valid. One extra entry
	// carries the run-level fact without libelling the individual hosts.
	if err := incompleteError(int(incomplete.Load())); err != nil {
		out = append(out, HostResult{Err: err})
	}
	return out
}

func nativeTLSSettings(hosts []string, metadata map[string]NativeMetadata) (enrich.TLSConfig, int, bool) {
	for _, host := range hosts {
		m := metadata[host]
		if !m.IdentifyTLS {
			continue
		}
		limit := m.TLSMaxEndpoints
		if limit <= 0 {
			limit = defaultTLSMaxEndpoints
		}
		return m.TLSConfig, limit, true
	}
	return enrich.TLSConfig{}, 0, false
}

func enrichNativeTLS(ctx context.Context, results []sweep.PortResult, metadata map[string]NativeMetadata, cfg enrich.TLSConfig, limit int) {
	endpoints := make([]string, 0, min(limit, len(results)))
	targets := make(map[string]struct {
		host string
		port int
	})
	for _, result := range results {
		for _, port := range result.Ports {
			if len(endpoints) >= limit {
				break
			}
			if !likelyTLSPort(port) {
				continue
			}
			endpoint := net.JoinHostPort(result.IP, strconv.Itoa(port.Port))
			endpoints = append(endpoints, endpoint)
			targets[endpoint] = struct {
				host string
				port int
			}{result.IP, port.Port}
		}
		if len(endpoints) >= limit {
			break
		}
	}
	for endpoint, cert := range enrich.LookupTLS(ctx, endpoints, cfg) {
		target := targets[endpoint]
		m := metadata[target.host]
		if m.TLS == nil {
			m.TLS = make(map[int]enrich.TLSInfo)
		}
		m.TLS[target.port] = cert
		metadata[target.host] = m
	}
}

func likelyTLSPort(port sweep.OpenPort) bool {
	switch port.Port {
	case 443, 465, 636, 989, 990, 993, 995, 5061, 8443:
		return true
	}
	service := strings.ToLower(port.Service)
	return strings.Contains(service, "tls") || strings.Contains(service, "ssl") ||
		strings.Contains(service, "https") || strings.HasSuffix(service, "s") &&
		(strings.Contains(service, "imap") || strings.Contains(service, "pop3") || strings.Contains(service, "smtp") || strings.Contains(service, "ldap"))
}

// syntheticXML renders a native port result as the subset of nmap's XML that
// ndscan's parser reads. Values are escaped so a hostile service name or
// address can't produce malformed output.
func syntheticXML(r sweep.PortResult, measuredRTT ...time.Duration) []byte {
	metadata := NativeMetadata{}
	if len(measuredRTT) > 0 {
		metadata.RTT = measuredRTT[0]
	}
	return syntheticXMLWithMetadata(r, metadata)
}

func syntheticXMLWithMetadata(r sweep.PortResult, metadata NativeMetadata) []byte {
	var b strings.Builder
	b.WriteString(`<nmaprun><host><status state="up"/><address addr="`)
	xml.EscapeText(&b, []byte(r.IP))
	b.WriteString(`" addrtype="ipv4"/>`)
	if metadata.RTT > 0 {
		// nmap's srtt unit is microseconds. Round up so a real sub-microsecond
		// loopback connect never turns into the sentinel value zero.
		us := (metadata.RTT + time.Microsecond - 1) / time.Microsecond
		b.WriteString(`<times srtt="`)
		b.WriteString(strconv.FormatInt(int64(us), 10))
		b.WriteString(`"/>`)
	}
	b.WriteString(`<ports>`)
	for _, p := range r.Ports {
		b.WriteString(`<port protocol="tcp" portid="`)
		b.WriteString(strconv.Itoa(p.Port))
		b.WriteString(`"><state state="open"/>`)
		cert, hasCert := metadata.TLS[p.Port]
		if p.Service != "" || hasCert {
			b.WriteString(`<service name="`)
			xml.EscapeText(&b, []byte(p.Service))
			if hasCert {
				b.WriteString(`" tunnel="ssl`)
				if cert.Organization != "" {
					b.WriteString(`" product="`)
					xml.EscapeText(&b, []byte(cert.Organization))
				}
			}
			b.WriteString(`"/>`)
		}
		if hasCert {
			writeTLSCertXML(&b, cert)
		}
		b.WriteString(`</port>`)
	}
	b.WriteString(`</ports></host></nmaprun>`)
	return []byte(b.String())
}

// SynthesizeNativeResult exposes the no-I/O XML conversion for pipeline code
// that enriches a completed open-port result before handing it to renderers.
func SynthesizeNativeResult(r sweep.PortResult, metadata NativeMetadata) HostResult {
	return HostResult{IP: r.IP, XMLBytes: syntheticXMLWithMetadata(r, metadata)}
}

func writeTLSCertXML(b *strings.Builder, cert enrich.TLSInfo) {
	b.WriteString(`<script id="ssl-cert"><table key="subject">`)
	writeCertElem(b, "commonName", cert.CommonName)
	writeCertElem(b, "organizationName", cert.Organization)
	b.WriteString(`</table><table key="issuer">`)
	writeCertElem(b, "commonName", cert.Issuer)
	b.WriteString(`</table><table key="validity">`)
	if !cert.NotAfter.IsZero() {
		writeCertElem(b, "notAfter", cert.NotAfter.Format("2006-01-02T15:04:05"))
	}
	b.WriteString(`</table></script>`)
}

func writeCertElem(b *strings.Builder, key, value string) {
	if value == "" {
		return
	}
	b.WriteString(`<elem key="`)
	b.WriteString(key)
	b.WriteString(`">`)
	xml.EscapeText(b, []byte(value))
	b.WriteString(`</elem>`)
}

// ValidatePorts reports whether a port specification is usable, without running
// anything. Front ends call it before a scan starts so a typo is a message at
// the prompt rather than an empty result table after the work is done — the
// native and nmap paths disagree about what malformed syntax means, and neither
// disagreement should be visible to a user who simply mistyped.
//
// An empty spec is valid: it means "use the preset's default ports".
func ValidatePorts(spec string) error {
	_, err := parsePortSpec(spec)
	return err
}

// parsePortSpec turns ndscan's port syntax ("22,80,443" or "1-1024", possibly
// mixed) into an explicit port list. Empty input deliberately returns nil so
// the sweep uses its default set; malformed input must never take that path.
func parsePortSpec(spec string) ([]int, error) {
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return nil, nil
	}
	seen := make(map[int]bool)
	var out []int
	add := func(p int) {
		if p >= 1 && p <= 65535 && !seen[p] {
			seen[p] = true
			out = append(out, p)
		}
	}
	for _, part := range strings.Split(spec, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			return nil, fmt.Errorf("invalid port token %q", part)
		}
		lo, hi, isRange := strings.Cut(part, "-")
		if !isRange {
			p, err := strconv.Atoi(part)
			if err != nil || p < 1 || p > 65535 {
				return nil, fmt.Errorf("invalid port token %q", part)
			}
			add(p)
			continue
		}
		start, err1 := strconv.Atoi(strings.TrimSpace(lo))
		end, err2 := strconv.Atoi(strings.TrimSpace(hi))
		if err1 != nil || err2 != nil || start < 1 || end > 65535 || start > end {
			return nil, fmt.Errorf("invalid port token %q", part)
		}
		for p := start; p <= end; p++ {
			add(p)
		}
	}
	return out, nil
}

func incompleteError(probes int) error {
	if probes == 0 {
		return nil
	}
	return fmt.Errorf("native port scan incomplete: %d probes skipped after file descriptor exhaustion", probes)
}

// NativePortScanViable reports whether a native port scan can serve this
// config. It cannot when the caller needs what only nmap provides: service
// versions, OS detection, or NSE output (the -A presets), or UDP.
func NativePortScanViable(cfg Config, runner Runner) bool {
	if _, local := runner.(LocalRunner); !local {
		return false // probes must originate from this machine
	}
	switch cfg.Preset {
	case "default", "deep", "udp":
		return false // these want nmap's -A / -sU capabilities
	}
	return true
}

// nativeScanBudget is how long a native port scan may run before the caller
// should consider it stalled. Native scans complete in well under a second per
// host on a LAN; this is a backstop, not a working limit.
const nativeScanBudget = 2 * time.Minute
