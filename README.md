# ndscan

A modern **CLI wrapper around nmap** that makes daily network discovery faster and more intuitive.  

Features:
- **Table view** (`-tb`) → clean list of hosts and open ports.
- **Tree view** (`-tr`) → hierarchical breakdown of hosts, status, MAC, vendor, and ports.
- **MAC address & vendor lookup** (`--show-mac --show-vendors`).
- **Run locally or remotely** → `user@host` syntax will SSH into a jump host and run scans from there.
- **JSON export** for automation pipelines.
- Modular Go code with Cobra CLI and pretty output.

---

## Install

Clone and build:
```bash
git clone https://github.com/Emre-Diricanli/ndscan.git
cd ndscan
go mod tidy
go build -o ndscan ./cmd/ndscan
```

Optionally move it into your $PATH:

```bash
sudo mv ndscan /usr/local/bin/
```
Or install directly with Go:

```bash
go install github.com/Emre-Diricanli/ndscan/cmd/ndscan@latest
```

## Usage
```bash
ndscan scan [user@remote] <targets> [flags]
```
## Examples: 
**Quick local scan in table view**
```bash
./ndscan scan 192.168.1.0/24 -tb
```
**Tree view with MAC + vendor**
```
./ndscan scan 192.168.1.0/24 -tr --show-mac --show-vendors
```
**Remote scan through SSH jump host**
```
./ndscan scan emre@203.0.113.10 192.168.0.0/24 -tb
```
**Export resutls as JSON**
```
./ndscan scan 192.168.1.0/24 -tr --json results.json
```
## Flags
| Flag             | Description                                                 |
| ---------------- | ----------------------------------------------------------- |
| `-tb`            | Shortcut: table view                                        |
| `-tr`            | Shortcut: tree view                                         |
| `--preset`       | Scan preset: `quick` (default), `default`, `udp`, `deep`    |
| `-p, --ports`    | Custom ports (e.g., `22,80,443` or `1-1024`)                |
| `--show-mac`     | Include MAC addresses (only works on same L2 segment)       |
| `--show-vendors` | Include vendor names (requires `--show-mac`)                |
| `--root-scan`    | Use SYN scan (`-sS`) instead of TCP connect (requires root) |
| `--json`         | Save results to JSON file                                   |
| `--concurrency`  | Max parallel host scans (default 32)                        |
| `--host-timeout` | Timeout per host in seconds (default 20)                    |
| `--view`         | Force view type: `table` or `tree`                          |

## Vendor Lookup
By default, ndscan ships with a small built-in OUI sample.
For more accurate vendor results, drop your own OUI file at:
```
~/.ndscan/oui.txt
```
Format (tab or space separated):
```
00:11:22   AcmeCorp
3C:5A:B4   TP-Link
48:5A:3F   Cisco
```
# Views
**Table view(`-tb`);**
```
+----------------+----------------+-----+----------------------+
| IP             | HOST           | UP  | OPEN PORTS           |
+----------------+----------------+-----+----------------------+
| 192.168.1.1    | _gateway       | yes | 53, 80, 8080, 8443   |
| 192.168.1.200  |                | yes | 22                   |
+----------------+----------------+-----+----------------------+
```
**Tree view(`-tr`);**
```
192.168.1.1
├─ Host: _gateway
├─ Up: yes
├─ MAC: 48:5A:3F:12:34:56
├─ Vendor: Cisco
└─ Ports:
   ├─ 53/tcp domain
   ├─ 80/tcp http
   └─ 8443/tcp https-alt
```
# Roadmap
- --ssh-sudo flag for automatic sudo nmap on jump hosts.

- Lightweight built-in port scanner for ultra-fast /24 sweeps.

- Banner grabbing (SSH/HTTP service info).

- History of past scans (ndscan history list).
