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
  "topology": { /* see Topology below */ },
  "watch": { "enabled": true, "intervalSec": 300, "nextAt": "2026-08-05T20:04:21Z" },
  "suggested": [
    { "cidr": "192.168.2.0/24", "interface": "en0", "addr": "192.168.2.157" }
  ],
  "siblings": ["192.168.1.0/24", "10.0.0.0/24"]
}
```
`topology` is `null` before the first scan. `lastScan` is `null` likewise.

`watch` mirrors the current watch-mode state (see `POST /api/watch`); `nextAt`
is present only while the loop is enabled. `suggested` lists the networks this
machine is attached to, so the UI can offer a target instead of an empty box —
the scanner already knows the answer to "what should I scan?". Only physical
interfaces qualify: tunnels and link-local networks would bury the one network
the user actually means. `siblings` holds the routed /24 candidates
`POST /api/scan/sweep` would probe, derived passively from the interface table,
so showing the choice never probes the network. Both are omitted when empty.

### `POST /api/scan`
Starts a scan. Returns `202 Accepted` immediately; progress arrives on
`/api/events`. Returns `409 Conflict` if a scan is already running.

Request:
```json
{ "targets": ["192.168.2.0/24"], "fast": true, "preset": "quick" }
```
`targets` required, non-empty. `fast` defaults true (native scanner).
`preset` one of `quick|smart|default|udp|deep`, defaults `quick`.

Response `202`:
```json
{ "started": true }
```
Error responses use `{"error": "message"}` with 4xx/5xx.

### `POST /api/scan/sweep`
Starts a routed sweep: every attached IPv4 network plus the sibling /24
candidates derived from the interface table (the same list `/api/state` shows
as `siblings`). Always runs with the `quick` preset and the native scanner —
a sweep exists to be fast, so neither is configurable here. Returns
`202 Accepted` immediately; progress arrives on `/api/events`.

Request (an empty body is allowed):
```json
{ "extra": ["10.0.7.0/24"] }
```
`extra` adds candidate subnets of your own — a bare IP is normalised to the
/24 around it — and is validated exactly like `scan` targets.

Response `202`:
```json
{ "started": true, "targets": ["192.168.2.0/24", "192.168.1.0/24"], "count": 1 }
```
`targets` is the full list the scan will cover; `count` is how many sibling
candidates were found beyond the attached networks. Returns `400 Bad Request`
when there are no sibling subnets to probe (no attached IPv4 /24 to derive
from, and nothing usable in `extra`) and `409 Conflict` if a scan is already
running.

### `POST /api/cancel`
Cancels the running scan. `200` with `{"cancelled": true}`, or `409` if idle.

### `POST /api/watch`
Turns watch mode on or off. Watch mode re-runs the scan on an interval and
reports what changed. The loop lives on the server deliberately: it survives a
closed tab, a reload, or a laptop lid, and every connected client sees the
same schedule instead of each keeping its own timer.

Request:
```json
{ "enabled": true, "intervalSec": 300, "targets": ["192.168.2.0/24"], "fast": true, "preset": "quick" }
```
`enabled: false` stops the loop; the other fields are then ignored. When
enabling, `targets` defaults to the last scan's targets, `preset` to `quick`,
and `fast` to true — targets and preset get the same validation a manual scan
gets, because watch mode is just a scan on a timer and a bad target must not
be accepted here only to fail silently every interval. An `intervalSec` below
15 is clamped to 15: watch mode exists to notice changes, not to hammer the
network.

Response `200`:
```json
{ "enabled": true, "intervalSec": 300, "nextAt": "2026-08-05T20:04:21Z" }
```
`intervalSec` reflects the clamped value; `nextAt` is the next scheduled
rescan and is omitted when disabling. The current state is also reported on
`/api/state`, and changes are broadcast as `watch` events on `/api/events`.

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

event: watch
data: {"enabled":true,"nextAt":"2026-08-05T20:04:21Z"}
```
`watch` reports watch-mode changes even when no scan is running:
`{"enabled":false}` when the loop stops, `{"enabled":true,"rescanning":true}`
when a scheduled rescan starts, and `nextAt` after each tick.

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
      "inferred": false,
      "notScanned": false,
      "routedVia": "",
      "nodes": [ /* Node */ ]
    }
  ],
  "orphans": [ /* Node */ ]
}
```
`interface` is empty for segments not attached to this machine.
`routedVia` is the gateway IP for subnets reached through it (a sibling VLAN);
empty for attached segments. A segment with `notScanned: true` is attached but
was not covered by the scan — render it as unknown, never as empty.

A segment with `inferred: true` has a boundary that was guessed rather than
observed on an interface or supplied as a scan target. Render it visibly
differently: a guessed boundary must never read as a measured fact.

`orphans` holds hosts that answered the scan but fall inside no attached
network and no scan target. They are outside `segments` precisely because no
CIDR honestly contains them, and they are omitted when empty. Render them —
a host that answered must not disappear from the map — but do not place them
under any network.

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
