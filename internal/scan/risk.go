package scan

import "strings"

// Severity ranks how noteworthy an open port is on a local network.
type Severity int

const (
	// SevNone means the port is unremarkable / expected.
	SevNone Severity = iota
	// SevInfo flags a service worth noticing (admin panels, databases).
	SevInfo
	// SevWarn flags a service that is commonly a security concern when
	// exposed (remote access, file sharing, legacy protocols).
	SevWarn
	// SevHigh flags a service that is almost always a problem to find open
	// (cleartext credentials, unauthenticated remote control).
	SevHigh
)

func (s Severity) String() string {
	switch s {
	case SevHigh:
		return "high"
	case SevWarn:
		return "warn"
	case SevInfo:
		return "info"
	default:
		return ""
	}
}

// PortRisk describes why an open port is interesting.
type PortRisk struct {
	Severity Severity
	Reason   string
}

// riskByPort maps well-known port numbers to a risk assessment. Keyed by the
// numeric port; the service name is used as a secondary signal in ClassifyPort.
var riskByPort = map[int]PortRisk{
	21:    {SevHigh, "FTP — often cleartext credentials"},
	23:    {SevHigh, "Telnet — cleartext, no encryption"},
	512:   {SevHigh, "rexec — legacy remote exec"},
	513:   {SevHigh, "rlogin — cleartext remote login"},
	514:   {SevHigh, "rsh — cleartext remote shell"},
	2049:  {SevHigh, "NFS — network file share"},
	3389:  {SevWarn, "RDP — remote desktop exposed"},
	5900:  {SevWarn, "VNC — remote desktop exposed"},
	5901:  {SevWarn, "VNC — remote desktop exposed"},
	445:   {SevWarn, "SMB — Windows file sharing exposed"},
	139:   {SevWarn, "NetBIOS — legacy Windows file sharing"},
	135:   {SevWarn, "MSRPC — Windows RPC endpoint"},
	3306:  {SevWarn, "MySQL — database reachable"},
	5432:  {SevWarn, "PostgreSQL — database reachable"},
	27017: {SevWarn, "MongoDB — database reachable"},
	6379:  {SevWarn, "Redis — often unauthenticated"},
	9200:  {SevWarn, "Elasticsearch — often unauthenticated"},
	11211: {SevWarn, "Memcached — often unauthenticated"},
	1433:  {SevWarn, "MS-SQL — database reachable"},
	22:    {SevInfo, "SSH — remote shell"},
	3000:  {SevInfo, "dev server / admin panel"},
	8080:  {SevInfo, "HTTP-alt — admin panel / proxy"},
	8443:  {SevInfo, "HTTPS-alt — admin panel"},
	8888:  {SevInfo, "HTTP-alt — admin panel"},
	9000:  {SevInfo, "admin panel / dev server"},
	161:   {SevInfo, "SNMP — device management"},
	631:   {SevInfo, "IPP — printing service"},
	5000:  {SevInfo, "UPnP / AirPlay / dev server"},
}

// riskByService matches on the nmap-reported service name when the port number
// alone isn't conclusive (non-standard ports running a notable service).
var riskByService = map[string]PortRisk{
	"telnet":        {SevHigh, "Telnet — cleartext, no encryption"},
	"ftp":           {SevHigh, "FTP — often cleartext credentials"},
	"microsoft-ds":  {SevWarn, "SMB — Windows file sharing exposed"},
	"netbios-ssn":   {SevWarn, "NetBIOS — legacy Windows file sharing"},
	"ms-wbt-server": {SevWarn, "RDP — remote desktop exposed"},
	"vnc":           {SevWarn, "VNC — remote desktop exposed"},
	"mysql":         {SevWarn, "MySQL — database reachable"},
	"postgresql":    {SevWarn, "PostgreSQL — database reachable"},
	"mongodb":       {SevWarn, "MongoDB — database reachable"},
	"redis":         {SevWarn, "Redis — often unauthenticated"},
	"ms-sql-s":      {SevWarn, "MS-SQL — database reachable"},
}

// ClassifyPort assesses an open port. It prefers a port-number match, then
// falls back to the service name, returning {SevNone} when nothing stands out.
func ClassifyPort(port int, service string) PortRisk {
	if r, ok := riskByPort[port]; ok {
		return r
	}
	if r, ok := riskByService[strings.ToLower(strings.TrimSpace(service))]; ok {
		return r
	}
	return PortRisk{Severity: SevNone}
}
