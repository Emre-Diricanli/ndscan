package sweep

import (
	"context"
	"net"
	"sort"
	"strconv"
	"sync"
	"time"
)

// TopPorts is nmap's --top-ports 100 set: the hundred TCP ports most likely to
// be open on a real host. Scanning these covers the overwhelming majority of
// services while staying fast enough to feel instant on a LAN.
var TopPorts = []int{
	7, 20, 21, 22, 23, 25, 26, 53, 80, 81, 88, 106, 110, 111, 113, 119, 135, 139,
	143, 144, 179, 199, 389, 427, 443, 444, 445, 465, 513, 514, 515, 543, 544,
	548, 554, 587, 631, 646, 873, 990, 993, 995, 1025, 1026, 1027, 1028, 1029,
	1110, 1433, 1720, 1723, 1755, 1900, 2000, 2001, 2049, 2121, 2717, 3000, 3128,
	3306, 3389, 3986, 4899, 5000, 5009, 5051, 5060, 5101, 5190, 5357, 5432, 5631,
	5666, 5800, 5900, 6000, 6001, 6646, 7070, 8000, 8008, 8009, 8080, 8081, 8443,
	8888, 9100, 9999, 10000, 32768, 49152, 49153, 49154, 49155, 49156, 49157,
}

// OpenPort is one port found open on a host.
type OpenPort struct {
	Port int
	// Service is the well-known name for the port number, or "". This is a
	// lookup, not a probe — native scanning does not do version detection.
	Service string
}

// PortResult holds the open ports discovered on one host.
type PortResult struct {
	IP    string
	Ports []OpenPort
}

// PortConfig tunes a native port scan.
type PortConfig struct {
	// Ports to probe. Defaults to TopPorts.
	Ports []int
	// Timeout per connect attempt. Defaults to 400ms — slightly more generous
	// than discovery, since a host known to be alive deserves a fairer chance
	// to answer on a slow service.
	Timeout time.Duration
	// Concurrency caps in-flight connections across all hosts. Defaults to
	// 2048, capped at maxConcurrency.
	Concurrency int
	// Progress, if set, is called as hosts complete. May be called from
	// multiple goroutines.
	Progress func(done, total int)
}

// ScanPorts probes the given hosts for open TCP ports using plain connects.
//
// This is the native replacement for shelling out to `nmap -sT`. On a LAN it is
// roughly two orders of magnitude faster for the same port set, because every
// probe runs concurrently under one timeout policy rather than being serialised
// behind nmap's per-host retry and rate-limiting logic.
//
// What it deliberately does NOT do: service version detection, OS fingerprinting,
// or NSE scripts. Those are nmap's genuine strengths and callers who need them
// should still use the nmap path.
func ScanPorts(ctx context.Context, hosts []string, cfg PortConfig) []PortResult {
	if len(cfg.Ports) == 0 {
		cfg.Ports = TopPorts
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 400 * time.Millisecond
	}
	if cfg.Concurrency <= 0 {
		cfg.Concurrency = 2048
	}
	if cfg.Concurrency > maxConcurrency {
		cfg.Concurrency = maxConcurrency
	}

	var (
		mu     sync.Mutex
		byHost = make(map[string][]OpenPort, len(hosts))
		wg     sync.WaitGroup
		sem    = make(chan struct{}, cfg.Concurrency)
		dialer = &net.Dialer{Timeout: cfg.Timeout}
		done   int
	)

	// One waitgroup per host lets progress report host completion rather than
	// probe completion, which is what a user actually wants to watch.
	for _, ip := range hosts {
		if ctx.Err() != nil {
			break
		}
		wg.Add(1)
		go func(ip string) {
			defer wg.Done()
			var hostWG sync.WaitGroup
			for _, port := range cfg.Ports {
				if ctx.Err() != nil {
					break
				}
				hostWG.Add(1)
				select {
				case sem <- struct{}{}:
				case <-ctx.Done():
					hostWG.Done()
					continue
				}
				go func(port int) {
					defer hostWG.Done()
					defer func() { <-sem }()
					conn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(ip, strconv.Itoa(port)))
					if err != nil {
						return
					}
					conn.Close()
					mu.Lock()
					byHost[ip] = append(byHost[ip], OpenPort{Port: port, Service: ServiceName(port)})
					mu.Unlock()
				}(port)
			}
			hostWG.Wait()

			mu.Lock()
			done++
			d := done
			mu.Unlock()
			if cfg.Progress != nil {
				cfg.Progress(d, len(hosts))
			}
		}(ip)
	}
	wg.Wait()

	out := make([]PortResult, 0, len(hosts))
	for _, ip := range hosts {
		ports := byHost[ip]
		sort.Slice(ports, func(i, j int) bool { return ports[i].Port < ports[j].Port })
		out = append(out, PortResult{IP: ip, Ports: ports})
	}
	return out
}

// serviceNames maps well-known ports to their service name, mirroring the
// labels nmap reports so output is consistent between the native and nmap
// paths. Unknown ports report "" rather than a guess.
var serviceNames = map[int]string{
	7: "echo", 20: "ftp-data", 21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp",
	26: "rsftp", 53: "domain", 80: "http", 81: "hosts2-ns", 88: "kerberos-sec",
	106: "pop3pw", 110: "pop3", 111: "rpcbind", 113: "ident", 119: "nntp",
	135: "msrpc", 139: "netbios-ssn", 143: "imap", 144: "news", 179: "bgp",
	199: "smux", 389: "ldap", 427: "svrloc", 443: "https", 444: "snpp",
	445: "microsoft-ds", 465: "smtps", 513: "login", 514: "shell",
	515: "printer", 543: "klogin", 544: "kshell", 548: "afp", 554: "rtsp",
	587: "submission", 631: "ipp", 646: "ldp", 873: "rsync", 990: "ftps",
	993: "imaps", 995: "pop3s", 1025: "NFS-or-IIS", 1026: "LSA-or-nterm",
	1027: "IIS", 1028: "unknown", 1029: "ms-lsa", 1110: "nfsd-status",
	1433: "ms-sql-s", 1720: "h323q931", 1723: "pptp", 1755: "wms",
	1900: "upnp", 2000: "cisco-sccp", 2001: "dc", 2049: "nfs",
	2121: "ccproxy-ftp", 2717: "pn-requester", 3000: "ppp", 3128: "squid-http",
	3306: "mysql", 3389: "ms-wbt-server", 3986: "mapper-ws_ethd",
	4899: "radmin", 5000: "upnp", 5009: "airport-admin", 5051: "ida-agent",
	5060: "sip", 5101: "admdog", 5190: "aol", 5357: "wsdapi",
	5432: "postgresql", 5631: "pcanywheredata", 5666: "nrpe", 5800: "vnc-http",
	5900: "vnc", 6000: "X11", 6001: "X11:1", 6646: "unknown", 7070: "realserver",
	8000: "http-alt", 8008: "http", 8009: "ajp13", 8080: "http-proxy",
	8081: "blackice-icecap", 8443: "https-alt", 8888: "sun-answerbook",
	9100: "jetdirect", 9999: "abyss", 10000: "snet-sensor-mgmt",
	32768: "filenet-tms", 49152: "unknown", 49153: "unknown", 49154: "unknown",
	49155: "unknown", 49156: "unknown", 49157: "unknown",
}

// ServiceName returns the well-known service name for a port, or "".
func ServiceName(port int) string { return serviceNames[port] }
