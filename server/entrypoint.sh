#!/bin/bash
set -e

# ─────────────────────────────────────────────────────────────
#  Colours for output
# ─────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'

log()  { echo -e "${CYAN}[SERVER]${RESET} $*"; }
ok()   { echo -e "${GREEN}[SERVER][OK]${RESET} $*"; }
warn() { echo -e "${YELLOW}[SERVER][WARN]${RESET} $*"; }

echo ""
echo -e "${BOLD}╔══════════════════════════════════════════════════════════╗"
echo -e "║   iptables + ipset + fail2ban Demo — Server Setup        ║"
echo -e "╚══════════════════════════════════════════════════════════╝${RESET}"
echo ""

# ─────────────────────────────────────────────────────────────
#  1. Flush all existing rules
# ─────────────────────────────────────────────────────────────
log "Flushing existing iptables rules..."
iptables -F
iptables -X
iptables -t mangle -F
iptables -t mangle -X
iptables -t nat -F
iptables -t nat -X
ok "All rules flushed."

# ─────────────────────────────────────────────────────────────
#  2. NAT table — POSTROUTING
#     :POSTROUTING ACCEPT [0:0]  ← policy, packets, bytes
#     MASQUERADE for outbound traffic (SNAT / NAT gateway demo)
# ─────────────────────────────────────────────────────────────
log "Setting up NAT table (POSTROUTING)..."
iptables -t nat -P POSTROUTING ACCEPT        # :POSTROUTING ACCEPT [0:0]
# MASQUERADE rewrites the source IP of outbound packets to the
# outgoing interface's IP — this is how home/office NAT works.
iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
ok "NAT POSTROUTING + MASQUERADE applied on eth0."

# DNAT example: redirect port 8888 → internal port 80
# iptables -t nat -A PREROUTING -p tcp --dport 8888 -j DNAT --to-destination 172.20.0.10:80
# (uncomment to demo port-forwarding / DNAT)

# ─────────────────────────────────────────────────────────────
#  3. Mangle table — PREROUTING (invalid / malformed packet drops)
#     All rules fire before routing, on every incoming packet.
# ─────────────────────────────────────────────────────────────
log "Applying mangle PREROUTING rules (anti-scan / TCP flag hardening)..."

# ── 3a. Conntrack: drop INVALID state packets ──────────────
# Packets that don't match any known connection and can't start one.
iptables -t mangle -A PREROUTING \
    -m conntrack --ctstate INVALID \
    -j DROP
log "  Rule 1: DROP INVALID conntrack state"

# ── 3b. Drop NEW connections that are not clean SYN ────────
# A legitimate new TCP connection must begin with only SYN set.
# If FIN,SYN,RST,ACK are checked and the result is NOT "only SYN",
# and this is a NEW connection → it's malformed, drop it.
iptables -t mangle -A PREROUTING \
    -p tcp -m tcp ! --tcp-flags FIN,SYN,RST,ACK SYN \
    -m conntrack --ctstate NEW \
    -j DROP
log "  Rule 2: DROP NEW connections that are not pure SYN"

# ── 3c. NULL scan (no flags at all) ────────────────────────
# Used for stealth port scanning. Never valid in real TCP.
iptables -t mangle -A PREROUTING \
    -p tcp -m tcp --tcp-flags FIN,SYN,RST,PSH,ACK,URG NONE \
    -j DROP
log "  Rule 3: DROP NULL scan (no TCP flags)"

# ── 3d. FIN + SYN simultaneously ───────────────────────────
# Contradictory: SYN opens, FIN closes — cannot be both.
iptables -t mangle -A PREROUTING \
    -p tcp -m tcp --tcp-flags FIN,SYN FIN,SYN \
    -j DROP
log "  Rule 4: DROP FIN+SYN (contradictory flags)"

# ── 3e. SYN + RST simultaneously ───────────────────────────
# Contradictory: SYN opens, RST aborts — never valid.
iptables -t mangle -A PREROUTING \
    -p tcp -m tcp --tcp-flags SYN,RST SYN,RST \
    -j DROP
log "  Rule 5: DROP SYN+RST (contradictory flags)"

# ── 3f. FIN + RST simultaneously ───────────────────────────
# Both mean "end connection" but via different mechanisms.
iptables -t mangle -A PREROUTING \
    -p tcp -m tcp --tcp-flags FIN,RST FIN,RST \
    -j DROP
log "  Rule 6: DROP FIN+RST (contradictory close mechanisms)"

# ── 3g. FIN without ACK ────────────────────────────────────
# FIN must always accompany ACK in valid TCP teardown.
iptables -t mangle -A PREROUTING \
    -p tcp -m tcp --tcp-flags FIN,ACK FIN \
    -j DROP
log "  Rule 7: DROP FIN without ACK"

# ── 3h. URG without ACK ────────────────────────────────────
# URG data requires ACK to be valid in the TCP stream.
iptables -t mangle -A PREROUTING \
    -p tcp -m tcp --tcp-flags ACK,URG URG \
    -j DROP
log "  Rule 8: DROP URG without ACK"

# ── 3i. PSH without ACK ────────────────────────────────────
# PSH is always used together with ACK in established connections.
iptables -t mangle -A PREROUTING \
    -p tcp -m tcp --tcp-flags PSH,ACK PSH \
    -j DROP
log "  Rule 9: DROP PSH without ACK"

# ── 3j. XMAS scan (all 6 flags set) ────────────────────────
# "Christmas tree" packet — lights up all flags. Used by Nmap.
iptables -t mangle -A PREROUTING \
    -p tcp -m tcp --tcp-flags FIN,SYN,RST,PSH,ACK,URG FIN,SYN,RST,PSH,ACK,URG \
    -j DROP
log "  Rule 10: DROP XMAS scan (all flags set)"

# ── 3k. FIN+PSH+URG (Nmap XMAS variant) ───────────────────
iptables -t mangle -A PREROUTING \
    -p tcp -m tcp --tcp-flags FIN,SYN,RST,PSH,ACK,URG FIN,PSH,URG \
    -j DROP
log "  Rule 11: DROP FIN+PSH+URG variant"

# ── 3l. FIN+SYN+PSH+URG ────────────────────────────────────
iptables -t mangle -A PREROUTING \
    -p tcp -m tcp --tcp-flags FIN,SYN,RST,PSH,ACK,URG FIN,SYN,PSH,URG \
    -j DROP
log "  Rule 12: DROP FIN+SYN+PSH+URG variant"

# ── 3m. FIN+SYN+RST+ACK+URG ────────────────────────────────
iptables -t mangle -A PREROUTING \
    -p tcp -m tcp --tcp-flags FIN,SYN,RST,PSH,ACK,URG FIN,SYN,RST,ACK,URG \
    -j DROP
log "  Rule 13: DROP FIN+SYN+RST+ACK+URG variant"

# ── 3n. Fragmented packets ──────────────────────────────────
# -f matches all non-first fragments. Fragmented packets can be
# used to bypass some packet filters or cause reassembly attacks.
iptables -t mangle -A PREROUTING -f -j DROP
log "  Rule 14: DROP fragmented IP packets"

# ─────────────────────────────────────────────────────────────
#  4. Filter table — INPUT: explicit IP block example
# ─────────────────────────────────────────────────────────────
iptables -A INPUT -s 172.20.0.99 -j DROP
log "  IP block: 172.20.0.99 blocked on INPUT"

# ─────────────────────────────────────────────────────────────
#  5. ipset — create named sets for bulk blocking
#
#  Three sets with different purposes:
#    ssh-blocklist   — managed by fail2ban; SSH scanners auto-added/expired
#    proxy-blocklist — loaded by fetch-proxies.sh; known proxy/exit-node CIDRs
#    manual-blocklist — ad-hoc static blocks for testing / manual ops
# ─────────────────────────────────────────────────────────────
echo ""
log "Creating ipsets..."

# ssh-blocklist: created by fail2ban's actionstart (needs timeout support).
# We do NOT pre-create it here so fail2ban can set it up with timeout=0.

# proxy-blocklist: hash:net supports CIDR ranges for efficient bulk blocking.
ipset create proxy-blocklist   hash:net maxelem 131072 -exist
ok "  Created: proxy-blocklist (hash:net, maxelem=131072)"

# manual-blocklist: hash:ip for individual ad-hoc IP blocks.
ipset create manual-blocklist  hash:ip  maxelem 65536  -exist
ok "  Created: manual-blocklist (hash:ip, maxelem=65536)"

# Wire ipsets into iptables INPUT chain.
# ssh-blocklist is wired by fail2ban's actionstart at startup.
iptables -A INPUT -m set --match-set proxy-blocklist  src -j DROP \
    -m comment --comment "ipset:proxy-blocklist"
iptables -A INPUT -m set --match-set manual-blocklist src -j DROP \
    -m comment --comment "ipset:manual-blocklist"
ok "iptables INPUT rules added for proxy-blocklist and manual-blocklist."

# ─────────────────────────────────────────────────────────────
#  6. Fetch public proxy list → proxy-blocklist
# ─────────────────────────────────────────────────────────────
echo ""
log "Running fetch-proxies.sh to populate proxy-blocklist..."
/fetch-proxies.sh || warn "fetch-proxies.sh exited non-zero (continuing)"

# ─────────────────────────────────────────────────────────────
#  7. SSH server
# ─────────────────────────────────────────────────────────────
echo ""
log "Starting SSH server..."
mkdir -p /run/sshd /var/log
touch /var/log/auth.log
# Set a demo root password (container only — never use in production)
echo "root:DemoPass123!" | chpasswd 2>/dev/null || true
/usr/sbin/sshd
ok "SSH server started on port 22 (demo password: DemoPass123!)"

# ─────────────────────────────────────────────────────────────
#  8. rsyslog — required for sshd → /var/log/auth.log pipeline
# ─────────────────────────────────────────────────────────────
log "Starting rsyslog (auth.log pipeline for fail2ban)..."
rsyslogd 2>/dev/null || warn "rsyslogd start failed — fail2ban log parsing may not work"
sleep 1

# ─────────────────────────────────────────────────────────────
#  9. fail2ban
# ─────────────────────────────────────────────────────────────
log "Starting fail2ban..."
fail2ban-client start 2>/dev/null || fail2ban-server -b -s /run/fail2ban/fail2ban.sock 2>/dev/null || warn "fail2ban start failed"
sleep 2

if fail2ban-client ping 2>/dev/null | grep -q pong; then
    ok "fail2ban running — sshd jail active (maxretry=3, findtime=30s, bantime=120s)"
else
    warn "fail2ban may not be running — check logs with: fail2ban-client status"
fi

# ─────────────────────────────────────────────────────────────
#  10. Print rule summary
# ─────────────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}── NAT table (POSTROUTING) ──────────────────────────────${RESET}"
iptables -t nat -L POSTROUTING -v -n --line-numbers
echo ""
echo -e "${BOLD}── Mangle table (PREROUTING) ────────────────────────────${RESET}"
iptables -t mangle -L PREROUTING -v -n --line-numbers
echo ""
echo -e "${BOLD}── Filter table (INPUT) — ipset rules ───────────────────${RESET}"
iptables -L INPUT -v -n --line-numbers
echo ""
echo -e "${BOLD}── ipset summary ────────────────────────────────────────${RESET}"
ipset list -t
echo ""
ok "All iptables + ipset rules applied successfully."

# ─────────────────────────────────────────────────────────────
#  11. Start HTTP server
# ─────────────────────────────────────────────────────────────
log "Starting HTTP server on port 80..."
echo ""
exec python3 -u /app/server.py
