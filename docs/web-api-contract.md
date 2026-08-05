# ndscan web API contract

Frozen interface between the Go server (`internal/web`) and the browser
frontend (`internal/web/static/`). Both sides are built independently against
this document; neither may change it unilaterally.

Server binds **127.0.0.1 only** by default. It is a network scanner with a
remote-control surface — exposing it beyond loopback requires an explicit flag.

## Endpoints

### `GET /api/state`
Current known state. Returns immediately; never scans.

```json
{
  "version": "0.1.1",
  "scanning": false,
  "targets": ["192.168.2.0/24"],
  "lastScan": "2026-08-05T19:54:21Z",
  "topology": { /* see Topology below */ }
}
```
`topology` is `null` before the first scan. `lastScan` is `null` likewise.

### `POST /api/scan`
Starts a scan. Returns `202 Accepted` immediately; progress arrives on
`/api/events`. Returns `409 Conflict` if a scan is already running.

Request:
```json
{ "targets": ["192.168.2.0/24"], "fast": true, "preset": "quick" }
```
`targets` required, non-empty. `fast` defaults true (native scanner).
`preset` one of `quick|default|udp|deep`, defaults `quick`.

Response `202`:
```json
{ "started": true }
```
Error responses use `{"error": "message"}` with 4xx/5xx.

### `POST /api/cancel`
Cancels the running scan. `200` with `{"cancelled": true}`, or `409` if idle.

### `GET /api/events` (Server-Sent Events)
Live scan progress. Event types:

```
event: phase
data: {"phase":"discover","done":42,"total":254}

event: host
data: { /* a single Host object, see below */ }

event: done
data: {"hosts":11,"openPorts":16,"elapsedMs":1683,"cancelled":false}

event: error
data: {"error":"message"}
```
Clients should reconnect on disconnect. The server sends a `: keepalive`
comment every 15s so proxies don't time the stream out.

### `GET /api/topology`
The current topology, same shape as `state.topology`. `null` before any scan.

### `GET /api/export?format=json|csv|md|html`
Downloads the most recently completed scan. JSON and CSV contain the same row
data as the TUI exports; Markdown and HTML use the shared report renderer.
Returns `409 Conflict` before a scan has completed and `400 Bad Request` for an
unsupported format. Successful responses include a timestamped
`Content-Disposition` filename such as `ndscan-20260805-195421.csv`.

### `GET /api/history`
Returns the previous snapshot for the current scan signature and its diff
against the current scan. This endpoint never reads or writes history on disk;
history is loaded, compared, and saved when a scan completes.

```json
{
  "hasPrevious": true,
  "previous": [{"ip":"192.168.2.1","host":"router","ports":["22/tcp ssh"]}],
  "diff": {
    "192.168.2.1": {"portsOpened":["443"],"portsClosed":["22"]},
    "192.168.2.50": {"new":true},
    "192.168.2.99": {"gone":true}
  }
}
```

Before the first scan, or when no prior matching scan exists, `hasPrevious` is
false and `diff` is `{}`. `previous` is omitted in that case.

### `POST /api/discover`
Runs a focused deep scan of exactly one literal IPv4 or IPv6 address, using the
default service/OS/scripts preset, the fixed Discover port set, and a 45-second
per-host budget. Hostnames, CIDRs, scanner options, and arbitrary strings are
rejected. The response is an enriched `Host`, including service versions, OS
guess, TLS certificate summaries, and HTTP titles when detected.

Request:
```json
{"ip":"192.168.2.50"}
```

Returns `404 Not Found` when the host produces no scan result.

## Types

### Topology
```json
{
  "gateway": "192.168.2.1",
  "segments": [
    {
      "cidr": "192.168.2.0/24",
      "interface": "en0",
      "selfAddr": "192.168.2.157",
      "notScanned": false,
      "routedVia": "",
      "nodes": [ /* Node */ ]
    }
  ]
}
```
`interface` is empty for segments not attached to this machine.
`routedVia` is the gateway IP for subnets reached through it (a sibling VLAN);
empty for attached segments. A segment with `notScanned: true` is attached but
was not covered by the scan — render it as unknown, never as empty.

### Node
```json
{
  "isGateway": false,
  "isSelf": false,
  "severity": "high",
  "host": { /* Host */ }
}
```
`severity` is one of `""`, `"info"`, `"warn"`, `"high"` — the worst among the
host's open ports.

### Host
```json
{
  "ip": "192.168.2.1",
  "hostname": "router",
  "mac": "aa:bb:cc:dd:ee:ff",
  "vendor": "Ubiquiti",
  "os": "Linux 5.X",
  "rtt": "3.1ms",
  "up": true,
  "ports": [
    { "port": 443, "proto": "tcp", "service": "https", "product": "nginx", "version": "1.26", "tls": true, "cert": "example — exp 2027-01-02", "httpTitle": "Admin", "severity": "info", "risk": "..." }
  ]
}
```
All string fields may be empty. `ports` may be empty or absent.

## Rules

- Every response is `application/json` except `/api/events` (`text/event-stream`)
  and successful `/api/export` downloads (the requested format's media type).
- Errors: `{"error": "..."}` with an appropriate status code.
- No endpoint blocks longer than a few ms except `/api/events`, which streams,
  and `/api/discover`, which waits for its focused scan (up to its time budget).
- The frontend is served from `/` as an embedded single page.
