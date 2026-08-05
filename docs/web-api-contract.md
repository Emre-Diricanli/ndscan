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
    { "port": 443, "proto": "tcp", "service": "https", "severity": "info", "risk": "..." }
  ]
}
```
All string fields may be empty. `ports` may be empty or absent.

## Rules

- Every response is `application/json` except `/api/events` (`text/event-stream`).
- Errors: `{"error": "..."}` with an appropriate status code.
- No endpoint blocks longer than a few ms except `/api/events`, which streams.
- The frontend is served from `/` as an embedded single page.
