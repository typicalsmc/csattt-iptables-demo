# iptables + ipset + fail2ban Demo — TCP Flag Filtering · IP Blocking · NAT · ipset · SSH Scanner Defense

A self-contained Docker Compose lab that demonstrates Linux firewall concepts through automated, live packet tests.

## Overview

Two containers run on an isolated bridge network (`172.25.0.0/24`):

| Container | IP | Role |
|---|---|---|
| `iptables_server` | `172.25.0.10` | HTTP + SSH server with hardened iptables/ipset/fail2ban ruleset |
| `iptables_client` | `172.25.0.20` | Test runner (Scapy + requests + paramiko) |

The **server** applies iptables rules, creates ipsets, fetches public proxy lists, starts sshd, and starts fail2ban at startup. The **client** crafts packets and verifies that each rule/mechanism behaves as expected.

## Prerequisites

- Docker and Docker Compose
- Linux host (or a Linux VM) — `privileged: true` is required for raw sockets, iptables, and ipset

## Quick Start

```bash
# Build and run — client output shows test results
docker compose up --build

# Run interactively
docker compose up --build -d
docker exec -it iptables_client bash
python3 /demo.py

# Run a specific test
docker exec -it iptables_client python3 /demo.py fail2ban_ssh_ban
docker exec -it iptables_client python3 /demo.py ipset_client_block
docker exec -it iptables_client python3 /demo.py proxy_blocklist

# List all test names
docker exec -it iptables_client python3 /demo.py --list
```

## Tests

The client runs 18 tests automatically.

### iptables / TCP Flag Tests (1–15)

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

### ipset + fail2ban Tests (16–18)

| # | Test | Expected |
|---|---|---|
| 16 | ipset client-side bulk block | BLOCKED then restored via ipset |
| 17 | fail2ban SSH ban (4 failed auth attempts) | IP added to `ssh-blocklist` ipset, SSH BLOCKED |
| 18 | proxy-blocklist populated by `fetch-proxies.sh` | PASS — entries present in ipset |

After the tests, the client prints an observational **NAT section** explaining POSTROUTING / MASQUERADE / DNAT.

### Running a single test

```bash
docker exec -it iptables_client python3 /demo.py <test_name_or_number>

# Examples
docker exec -it iptables_client python3 /demo.py null_scan
docker exec -it iptables_client python3 /demo.py 17
docker exec -it iptables_client python3 /demo.py fail2ban_ssh_ban

# List all test names
docker exec -it iptables_client python3 /demo.py --list
```

## Server Firewall Rules

Rules are applied by `server/entrypoint.sh` before the HTTP server starts:

### iptables (mangle / nat / filter)

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
| `filter` | INPUT | DROP src in `proxy-blocklist` ipset |
| `filter` | INPUT | DROP src in `manual-blocklist` ipset |
| `filter` | INPUT | DROP src in `ssh-blocklist` ipset (managed by fail2ban) |

### ipsets

| Name | Type | Managed by | Purpose |
|---|---|---|---|
| `ssh-blocklist` | `hash:ip` | fail2ban | SSH scanner IPs auto-added with 120s TTL |
| `proxy-blocklist` | `hash:net` | `fetch-proxies.sh` | Known proxy / Tor exit-node CIDRs |
| `manual-blocklist` | `hash:ip` | manual ops | Ad-hoc static IP blocks |

### fail2ban

| Parameter | Value | Description |
|---|---|---|
| `maxretry` | 3 | Failed SSH attempts before ban |
| `findtime` | 30s | Window for counting failures |
| `bantime` | 120s | How long the IP is blocked |
| `action` | `ipset-ssh` | Custom action — adds to `ssh-blocklist` ipset with timeout |
| `logpath` | `/var/log/auth.log` | sshd authentication log (via rsyslog) |

## Utility Scripts

### fetch-proxies.sh

Downloads public proxy lists and loads IPs into the `proxy-blocklist` ipset.

```bash
# Run inside the server container
docker exec iptables_server /fetch-proxies.sh
docker exec iptables_server /fetch-proxies.sh --dry-run   # preview only
docker exec iptables_server /fetch-proxies.sh --verbose   # print each IP
docker exec iptables_server /fetch-proxies.sh --stats     # show ipset stats after
```

Sources fetched:
- `TheSpeedX/PROXY-List` (GitHub raw)
- `clarketm/proxy-list` (GitHub raw)
- `ShiftyTR/Proxy-List` (GitHub raw)

Falls back to a built-in set of known proxy/Tor CIDRs if all remote sources are unreachable.

### test-ipset-fail2ban.sh

Standalone server-side test suite for ipset and fail2ban (runs inside the server container).

```bash
docker exec iptables_server /test-ipset-fail2ban.sh
```

Tests:
1. All three ipsets exist
2. iptables INPUT rules reference ipsets
3. `manual-blocklist` add / remove an IP
4. `proxy-blocklist` is populated
5. fail2ban is running and responding
6. fail2ban sshd jail is active
7. Manual fail2ban ban → ipset → unban cycle
8. ipset entry auto-expires after timeout

## Manual ipset Operations

```bash
# Enter the server container
docker exec -it iptables_server bash

# List all ipsets and their stats
ipset list -t

# Add an IP to the manual blocklist
ipset add manual-blocklist 1.2.3.4

# Remove an IP
ipset del manual-blocklist 1.2.3.4

# Check if an IP is in a set
ipset test manual-blocklist 1.2.3.4

# Check what fail2ban has banned
fail2ban-client status sshd

# Manually ban / unban via fail2ban
fail2ban-client set sshd banip 1.2.3.4
fail2ban-client set sshd unbanip 1.2.3.4

# Re-run proxy fetch
/fetch-proxies.sh --stats
```

## Project Structure

```
.
├── docker-compose.yml
├── server/
│   ├── Dockerfile               # Ubuntu 22.04 + iptables + ipset + fail2ban + openssh + Python
│   ├── entrypoint.sh            # Applies rules, starts sshd/rsyslog/fail2ban, runs fetch-proxies.sh
│   ├── server.py                # HTTP server — GET / and GET /ipset/<name>
│   ├── sshd_config              # Demo SSH server config (password auth enabled)
│   ├── fail2ban-jail.local      # fail2ban jail config for sshd → ipset-ssh action
│   ├── ipset-ssh.conf           # Custom fail2ban action using ipset
│   ├── fetch-proxies.sh         # Downloads proxy lists → proxy-blocklist ipset
│   └── test-ipset-fail2ban.sh   # Standalone server-side test suite
└── client/
    ├── Dockerfile               # python:3.11-slim + Scapy + requests + paramiko + ipset
    └── demo.py                  # Automated test suite (18 tests)
```

## Environment Variables

| Variable | Default | Description |
|---|---|---|
| `SERVER_IP` | `172.25.0.10` | Server IP address |
| `CLIENT_IP` | `172.25.0.20` | Client IP address |
| `SERVER_PORT` | `80` | Server HTTP port |
| `SSH_PORT` | `22` | Server SSH port |
| `SCAPY_TIMEOUT` | `2` | Seconds to wait for a raw packet response |
