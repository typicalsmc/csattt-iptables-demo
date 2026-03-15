# iptables Demo — TCP Flag Filtering · IP Blocking · NAT

A self-contained Docker Compose lab that demonstrates Linux `iptables` firewall concepts through automated, live packet tests.

## Overview

Two containers run on an isolated bridge network (`172.25.0.0/24`):

| Container | IP | Role |
|---|---|---|
| `iptables_server` | `172.25.0.10` | HTTP server with hardened iptables ruleset |
| `iptables_client` | `172.25.0.20` | Test runner (Scapy + requests) |

The **server** applies iptables rules at startup (NAT, mangle PREROUTING, filter INPUT). The **client** crafts raw TCP packets using [Scapy](https://scapy.net/) and verifies that each rule behaves as expected.

## Prerequisites

- Docker and Docker Compose
- Linux host (or a Linux VM) — `privileged: true` is required for raw sockets and iptables

## Quick Start

```bash
# Build and run — client output shows test results
docker compose up --build

# Run interactively
docker compose up --build -d
docker exec -it iptables_client bash
python3 /demo.py
```

The server is also reachable from the host at `http://localhost:8080/` for manual testing.

## Tests

The client runs 15 tests automatically. Each test shows the matching iptables rule, the expected outcome, and the actual result.

| # | Test | Expected |
|---|---|---|
| 1 | Normal HTTP GET | PASS — valid traffic allowed |
| 2 | NULL scan (no flags, `0x00`) | BLOCKED |
| 3 | XMAS scan (all 6 flags) | BLOCKED |
| 4 | FIN + SYN | BLOCKED |
| 5 | SYN + RST | BLOCKED |
| 6 | FIN + RST | BLOCKED |
| 7 | FIN without ACK | BLOCKED |
| 8 | URG without ACK | BLOCKED |
| 9 | PSH without ACK | BLOCKED |
| 10 | FIN + PSH + URG (Nmap XMAS variant) | BLOCKED |
| 11 | FIN + SYN + PSH + URG | BLOCKED |
| 12 | FIN + SYN + RST + ACK + URG | BLOCKED |
| 13 | Invalid conntrack state (bare ACK) | BLOCKED |
| 14 | Fragmented IP packet | BLOCKED |
| 15 | IP blocking (dynamic OUTPUT DROP) | BLOCKED then restored |

After the tests, the client prints an observational **NAT section** explaining POSTROUTING / MASQUERADE / DNAT.

### Running a single test

```bash
docker exec -it iptables_client python3 /demo.py <test_name_or_number>

# Examples
docker exec -it iptables_client python3 /demo.py null_scan
docker exec -it iptables_client python3 /demo.py 3

# List all test names
docker exec -it iptables_client python3 /demo.py --list
```

## Server Firewall Rules

Rules are applied by `server/entrypoint.sh` before the HTTP server starts:

| Table | Chain | Rule |
|---|---|---|
| `nat` | POSTROUTING | MASQUERADE on `eth0` (SNAT) |
| `mangle` | PREROUTING | DROP INVALID conntrack state |
| `mangle` | PREROUTING | DROP NEW connections that are not pure SYN |
| `mangle` | PREROUTING | DROP NULL scan (no flags) |
| `mangle` | PREROUTING | DROP FIN+SYN, SYN+RST, FIN+RST |
| `mangle` | PREROUTING | DROP FIN/URG/PSH without ACK |
| `mangle` | PREROUTING | DROP XMAS scan and variants |
| `mangle` | PREROUTING | DROP fragmented packets |
| `filter` | INPUT | DROP `172.20.0.99` (static IP block example) |

## Project Structure

```
.
├── docker-compose.yml
├── server/
│   ├── Dockerfile          # Ubuntu 22.04 + iptables + Python
│   ├── entrypoint.sh       # Applies iptables rules, then starts server
│   └── server.py           # Minimal HTTP server (logs client IP + path)
└── client/
    ├── Dockerfile          # python:3.11-slim + Scapy + requests
    └── demo.py             # Automated test suite
```

## Environment Variables

| Variable | Default | Description |
|---|---|---|
| `SERVER_IP` | `172.25.0.10` | Server IP address |
| `CLIENT_IP` | `172.25.0.20` | Client IP address |
| `SERVER_PORT` | `80` | Server port |
| `SCAPY_TIMEOUT` | `2` | Seconds to wait for a raw packet response |
