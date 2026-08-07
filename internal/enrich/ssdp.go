package enrich

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"
)

const (
	ssdpGroup = "239.255.255.250"
	ssdpPort  = 1900

	defaultSSDPTimeout = 2 * time.Second
	defaultSSDPMaxWait = 1
)

// defaultSSDPSearchTargets asks for everything; root devices are the
// fall-back because some appliances only answer their exact type.
var defaultSSDPSearchTargets = []string{"ssdp:all", "upnp:rootdevice"}

// SSDPConfig bounds a passive SSDP discovery pass. The zero value listens for
// two seconds and advertises a one-second MX so responders answer promptly.
type SSDPConfig struct {
	Timeout       time.Duration
	MaxWait       int
	SearchTargets []string
}

func (cfg SSDPConfig) withDefaults() SSDPConfig {
	if cfg.Timeout <= 0 {
		cfg.Timeout = defaultSSDPTimeout
	}
	if cfg.MaxWait <= 0 {
		cfg.MaxWait = defaultSSDPMaxWait
	}
	if len(cfg.SearchTargets) == 0 {
		cfg.SearchTargets = defaultSSDPSearchTargets
	}
	return cfg
}

// LookupSSDP discovers UPnP devices with an M-SEARCH burst and returns
// IP -> label for whatever answered before the deadline. The LOCATION URL is
// deliberately never fetched: following it would be an active HTTP request to
// an arbitrary host, and passive discovery must not do that. Failure to send
// or receive yields an empty or partial map, never an error.
func LookupSSDP(ctx context.Context, cfg SSDPConfig) map[string]string {
	cfg = cfg.withDefaults()
	ctx, cancel := context.WithTimeout(ctx, cfg.Timeout)
	defer cancel()

	// An ephemeral port is correct here: M-SEARCH responses are unicast back
	// to the sender, so no multicast join is needed to receive them.
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{Port: 0})
	if err != nil {
		return map[string]string{}
	}
	defer conn.Close()

	dst := &net.UDPAddr{IP: net.ParseIP(ssdpGroup), Port: ssdpPort}
	for _, st := range cfg.SearchTargets {
		// A failed send only means fewer answers; the listener still stands.
		_, _ = conn.WriteToUDP(buildMSearch(st, cfg.MaxWait), dst)
	}

	results := make(map[string]string)
	readUntil(ctx, conn, func(src *net.UDPAddr, b []byte) {
		absorbSSDPPacket(results, src, b)
	})
	return results
}

// absorbSSDPPacket folds one M-SEARCH response into the results. First label
// seen wins, so a device answering several search targets keeps one identity.
func absorbSSDPPacket(results map[string]string, src *net.UDPAddr, b []byte) {
	if label := ssdpLabel(parseSSDPHeaders(b)); label != "" {
		ip := src.IP.String()
		if _, ok := results[ip]; !ok {
			results[ip] = label
		}
	}
}

// buildMSearch encodes an M-SEARCH request. MX stays small: this is a
// discovery pass inside a scan budget, not a household census.
func buildMSearch(searchTarget string, maxWait int) []byte {
	return []byte(fmt.Sprintf(
		"M-SEARCH * HTTP/1.1\r\n"+
			"HOST: %s:%d\r\n"+
			"MAN: \"ssdp:discover\"\r\n"+
			"MX: %d\r\n"+
			"ST: %s\r\n"+
			"\r\n", ssdpGroup, ssdpPort, maxWait, searchTarget))
}

// parseSSDPHeaders decodes the HTTP-ish response into a lowercase-keyed
// header map. Devices in the wild are sloppy with line endings and spacing,
// so parsing is forgiving: bare LF is accepted and unknown junk lines are
// skipped.
func parseSSDPHeaders(data []byte) map[string]string {
	headers := make(map[string]string)
	for i, line := range strings.Split(string(data), "\n") {
		line = strings.TrimRight(line, "\r")
		if i == 0 {
			// Status line, e.g. 'HTTP/1.1 200 OK' — not a header.
			continue
		}
		key, value, found := strings.Cut(line, ":")
		if !found {
			continue
		}
		key = strings.ToLower(strings.TrimSpace(key))
		if key != "" {
			headers[key] = strings.TrimSpace(value)
		}
	}
	return headers
}

// ssdpLabel derives a display label from response headers. The SERVER header
// is preferred, minus the protocol boilerplate tokens that say nothing about
// the device; USN is the fallback, reduced to its UUID. Devices that reveal
// nothing get no label rather than a useless one.
func ssdpLabel(headers map[string]string) string {
	if server := headers["server"]; server != "" {
		var keep []string
		for _, field := range strings.Fields(server) {
			if strings.HasPrefix(field, "UPnP/") || strings.HasPrefix(field, "DLNADOC/") {
				continue
			}
			keep = append(keep, field)
		}
		if len(keep) > 0 {
			return strings.Join(keep, " ")
		}
	}
	usn := strings.TrimPrefix(headers["usn"], "uuid:")
	if i := strings.Index(usn, "::"); i >= 0 {
		usn = usn[:i]
	}
	return usn
}
