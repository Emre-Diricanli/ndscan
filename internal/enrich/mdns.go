package enrich

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"strings"
	"sync"
	"time"
)

const (
	mdnsGroup4 = "224.0.0.251"
	mdnsGroup6 = "ff02::fb"
	mdnsPort   = 5353

	defaultMDNSTimeout = 2500 * time.Millisecond

	dnsHeaderLen = 12
	dnsTypePTR   = 12
	dnsTypeA     = 1
	dnsTypeAAAA  = 28
	dnsClassIN   = 1

	// maxNameJumps bounds compression-pointer chasing so a malformed packet
	// cannot loop the parser forever.
	maxNameJumps = 32

	// readSlice is how long each socket read waits before re-checking the
	// context, so cancellation is honored even when no packet ever arrives.
	readSlice = 100 * time.Millisecond
)

// defaultMDNSServiceTypes covers the services that actually identify consumer
// LAN devices: printers, TVs, speakers, and admin access points.
var defaultMDNSServiceTypes = []string{
	"_http._tcp.local",
	"_printer._tcp.local",
	"_ipp._tcp.local",
	"_airplay._tcp.local",
	"_googlecast._tcp.local",
	"_raop._tcp.local",
	"_ssh._tcp.local",
	"_smb._tcp.local",
	"_workstation._tcp.local",
}

// MDNSConfig bounds a passive mDNS discovery pass. The zero value listens for
// 2.5 seconds and queries a curated set of common service types.
type MDNSConfig struct {
	Timeout      time.Duration
	ServiceTypes []string
	IPv6         bool
}

func (cfg MDNSConfig) withDefaults() MDNSConfig {
	if cfg.Timeout <= 0 {
		cfg.Timeout = defaultMDNSTimeout
	}
	if len(cfg.ServiceTypes) == 0 {
		cfg.ServiceTypes = defaultMDNSServiceTypes
	}
	return cfg
}

// packetReader is the slice of *net.UDPConn behavior the discovery loops
// need. Keeping it narrow lets tests drive the loops over loopback sockets
// without touching multicast or the host's real interfaces.
type packetReader interface {
	ReadFromUDP(b []byte) (n int, addr *net.UDPAddr, err error)
	SetReadDeadline(t time.Time) error
}

// LookupMDNS passively discovers device names via multicast DNS and returns
// IP -> friendly name for whatever answered before the deadline. A machine
// without multicast support, or a network with no responders, yields an empty
// or partial map — never an error, matching LookupPTR's contract.
func LookupMDNS(ctx context.Context, cfg MDNSConfig) map[string]string {
	cfg = cfg.withDefaults()
	ctx, cancel := context.WithTimeout(ctx, cfg.Timeout)
	defer cancel()

	conns := openMDNSListeners()
	if len(conns) == 0 {
		return map[string]string{}
	}
	defer func() {
		for _, c := range conns {
			_ = c.Close()
		}
	}()

	// Every joined interface is queried concurrently. A responder answers on
	// the interface the query arrived on, so listening on only one means
	// hearing only that segment — and the first joinable interface on a Mac is
	// loopback, where nothing on the LAN will ever reply.
	var (
		mu      sync.Mutex
		results = map[string]string{}
		wg      sync.WaitGroup
	)
	merge := func(from map[string]string) {
		mu.Lock()
		defer mu.Unlock()
		for ip, name := range from {
			if _, ok := results[ip]; !ok {
				results[ip] = name
			}
		}
	}
	for _, c := range conns {
		wg.Add(1)
		go func(c *net.UDPConn) {
			defer wg.Done()
			merge(runMDNS(ctx, cfg, c, &net.UDPAddr{IP: net.ParseIP(mdnsGroup4), Port: mdnsPort}))
			if cfg.IPv6 {
				// A bonus pass on the same listener; its failure changes
				// nothing about the IPv4 results already gathered.
				merge(runMDNS(ctx, cfg, c, &net.UDPAddr{IP: net.ParseIP(mdnsGroup6), Port: mdnsPort}))
			}
		}(c)
	}
	wg.Wait()
	return results
}

// runMDNS sends one query burst to dst and absorbs answers until ctx expires.
// It is split from LookupMDNS so tests can aim it at a loopback responder.
func runMDNS(ctx context.Context, cfg MDNSConfig, conn *net.UDPConn, dst *net.UDPAddr) map[string]string {
	unicast := conn.LocalAddr().(*net.UDPAddr).Port != mdnsPort
	query := buildMDNSQuery(cfg.ServiceTypes, unicast)
	// A failed send only means fewer answers; the listener below still stands.
	_, _ = conn.WriteToUDP(query, dst)

	results := make(map[string]string)
	readUntil(ctx, conn, func(src *net.UDPAddr, b []byte) {
		absorbMDNSPacket(results, src, b)
	})
	return results
}

// openMDNSListeners joins the mDNS group on every multicast-capable interface
// that could carry LAN traffic.
//
// Joining just one is not enough, and joining the *first* is actively wrong:
// responders answer on the interface the query arrived on, and on macOS the
// first multicast-capable interface is loopback, where nothing on the network
// will ever reply. That failure is silent — the socket binds, the query sends,
// and no packet ever arrives.
//
// Loopback is skipped for the same reason. Every fallback is deliberate:
// partial discovery beats no discovery.
func openMDNSListeners() []*net.UDPConn {
	group := &net.UDPAddr{IP: net.ParseIP(mdnsGroup4), Port: mdnsPort}
	var conns []*net.UDPConn

	if ifaces, err := net.Interfaces(); err == nil {
		for i := range ifaces {
			ifi := &ifaces[i]
			if ifi.Flags&net.FlagUp == 0 || ifi.Flags&net.FlagMulticast == 0 {
				continue
			}
			if ifi.Flags&net.FlagLoopback != 0 {
				continue // no responders live here
			}
			if conn, err := net.ListenMulticastUDP("udp4", ifi, group); err == nil {
				conns = append(conns, conn)
			}
		}
	}
	if len(conns) > 0 {
		return conns
	}

	// No joinable interface (or the port is taken): a plain bind still receives
	// unicast replies when we set the QU bit on questions.
	if conn, err := net.ListenUDP("udp4", &net.UDPAddr{Port: mdnsPort}); err == nil {
		return []*net.UDPConn{conn}
	}
	if conn, err := net.ListenUDP("udp4", &net.UDPAddr{Port: 0}); err == nil {
		return []*net.UDPConn{conn}
	}
	return nil
}

// readUntil absorbs packets until ctx is done or the socket breaks. Read
// deadlines are capped at readSlice so a cancelled context is noticed quickly
// even on a silent network.
func readUntil(ctx context.Context, conn packetReader, absorb func(src *net.UDPAddr, b []byte)) {
	buf := make([]byte, 65535)
	for ctx.Err() == nil {
		wait := readSlice
		if deadline, ok := ctx.Deadline(); ok {
			if remaining := time.Until(deadline); remaining < wait {
				wait = remaining
			}
		}
		if wait <= 0 {
			return
		}
		_ = conn.SetReadDeadline(time.Now().Add(wait))
		n, src, err := conn.ReadFromUDP(buf)
		if err != nil {
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				continue
			}
			// Socket closed or otherwise broken: keep whatever we have.
			return
		}
		absorb(src, buf[:n])
	}
}

// buildMDNSQuery encodes a PTR query for the DNS-SD service enumeration meta-
// type plus each service type. unicast sets the QU bit, asking responders to
// reply directly to us — required when we could not bind port 5353, since
// RFC 6762 multicast replies are only sent to queries sourced from 5353.
func buildMDNSQuery(serviceTypes []string, unicast bool) []byte {
	questions := make([]string, 0, len(serviceTypes)+1)
	questions = append(questions, "_services._dns-sd._udp.local")
	questions = append(questions, serviceTypes...)

	msg := make([]byte, dnsHeaderLen)
	binary.BigEndian.PutUint16(msg[4:6], uint16(len(questions)))

	class := uint16(dnsClassIN)
	if unicast {
		class |= 0x8000
	}
	for _, q := range questions {
		msg = append(msg, encodeName(q)...)
		msg = binary.BigEndian.AppendUint16(msg, dnsTypePTR)
		msg = binary.BigEndian.AppendUint16(msg, class)
	}
	return msg
}

// encodeName writes a dotted name in DNS label format. An empty name encodes
// as the root label.
func encodeName(name string) []byte {
	name = strings.TrimSuffix(name, ".")
	if name == "" {
		return []byte{0}
	}
	var out []byte
	for _, label := range strings.Split(name, ".") {
		out = append(out, byte(len(label)))
		out = append(out, label...)
	}
	return append(out, 0)
}

// parseName reads a possibly compressed name at off and returns it dotted,
// along with the offset just past the name at its original position.
func parseName(msg []byte, off int) (string, int, error) {
	var labels []string
	next := -1 // offset past the name, fixed once we jump or finish
	jumps := 0
	for {
		if off >= len(msg) {
			return "", 0, errors.New("name runs past end of message")
		}
		length := int(msg[off])
		switch {
		case length&0xC0 == 0xC0:
			if off+1 >= len(msg) {
				return "", 0, errors.New("truncated compression pointer")
			}
			if next == -1 {
				next = off + 2
			}
			jumps++
			if jumps > maxNameJumps {
				return "", 0, errors.New("compression pointer loop")
			}
			off = length&0x3F<<8 | int(msg[off+1])
		case length == 0:
			if next == -1 {
				next = off + 1
			}
			return strings.Join(labels, "."), next, nil
		case length&0xC0 == 0:
			if off+1+length > len(msg) {
				return "", 0, errors.New("label runs past end of message")
			}
			labels = append(labels, string(msg[off+1:off+1+length]))
			off += 1 + length
		default:
			return "", 0, errors.New("invalid label type")
		}
	}
}

// mdnsMessage is the subset of a DNS message discovery cares about: PTR
// targets (advertised instance names) and name -> IP address mappings from
// A/AAAA records in any section.
type mdnsMessage struct {
	ptrTargets []string
	addrs      map[string][]string
}

// parseMDNSMessage decodes a DNS packet. Anything malformed returns an error
// and the caller drops the packet — one garbage datagram must not poison a
// whole discovery pass.
func parseMDNSMessage(msg []byte) (mdnsMessage, error) {
	var out mdnsMessage
	if len(msg) < dnsHeaderLen {
		return out, errors.New("truncated header")
	}
	qd := int(binary.BigEndian.Uint16(msg[4:6]))
	records := int(binary.BigEndian.Uint16(msg[6:8])) +
		int(binary.BigEndian.Uint16(msg[8:10])) +
		int(binary.BigEndian.Uint16(msg[10:12]))

	off := dnsHeaderLen
	for range qd {
		_, next, err := parseName(msg, off)
		if err != nil {
			return out, err
		}
		off = next + 4 // qtype + qclass
		if off > len(msg) {
			return out, errors.New("truncated question")
		}
	}

	out.addrs = make(map[string][]string)
	for range records {
		name, next, err := parseName(msg, off)
		if err != nil {
			return out, err
		}
		off = next
		if off+10 > len(msg) {
			return out, errors.New("truncated record header")
		}
		rtype := binary.BigEndian.Uint16(msg[off : off+2])
		rdlen := int(binary.BigEndian.Uint16(msg[off+8 : off+10]))
		off += 10
		if off+rdlen > len(msg) {
			return out, errors.New("truncated rdata")
		}
		switch rtype {
		case dnsTypePTR:
			if target, _, err := parseName(msg, off); err == nil {
				out.ptrTargets = append(out.ptrTargets, target)
			}
		case dnsTypeA:
			if rdlen == 4 {
				out.addrs[name] = append(out.addrs[name], net.IP(msg[off:off+4]).String())
			}
		case dnsTypeAAAA:
			if rdlen == 16 {
				out.addrs[name] = append(out.addrs[name], net.IP(msg[off:off+16]).String())
			}
		}
		off += rdlen
	}
	return out, nil
}

// absorbMDNSPacket folds one response into the results. Names that come with
// their own A/AAAA record are authoritative; otherwise the responder's source
// address takes the cleaned name of its first advertised instance. First name
// seen wins so a chatty device cannot keep rewriting itself.
func absorbMDNSPacket(results map[string]string, src *net.UDPAddr, msg []byte) {
	parsed, err := parseMDNSMessage(msg)
	if err != nil {
		return
	}
	for name, ips := range parsed.addrs {
		clean := cleanMDNSName(name)
		if clean == "" {
			continue
		}
		for _, ip := range ips {
			if _, ok := results[ip]; !ok {
				results[ip] = clean
			}
		}
	}
	// Deliberately no fallback to the packet's source address. A PTR target
	// names a service, not the host that sent the datagram, and the two differ
	// exactly where it matters: a gateway or AP that relays mDNS between
	// segments would be labelled with whatever it last forwarded. On a real
	// network that produced a UniFi gateway confidently named "Canon MF460
	// Series". Only an address the packet actually asserts — an A or AAAA
	// record — identifies a host.
	_ = src
}

// cleanMDNSName turns a DNS-SD name into a display name: 'Living-Room-TV.
// _airplay._tcp.local.' becomes 'Living-Room-TV'. Names that are themselves
// service types (leading underscore) are not device names and yield "".
func cleanMDNSName(name string) string {
	name = strings.TrimSuffix(strings.TrimSpace(name), ".")
	lower := strings.ToLower(name)
	if strings.HasSuffix(lower, ".local") {
		name = name[:len(name)-len(".local")]
		lower = lower[:len(lower)-len(".local")]
	}
	// A leading underscore means the whole name is a service type, e.g.
	// '_ssh._tcp.local' — not a device name.
	if strings.HasPrefix(name, "_") {
		return ""
	}
	if i := strings.Index(lower, "._"); i > 0 {
		name = name[:i]
	}
	return name
}
