#!/bin/bash
# test-ipset-fail2ban.sh — Standalone tests for ipset and fail2ban inside the server container.
#
# Run from inside the container:
#   docker exec iptables_server /test-ipset-fail2ban.sh
#
# Tests:
#   1. ipset sets exist and are wired into iptables
#   2. Manual IP add/remove on manual-blocklist
#   3. Proxy-blocklist has entries (loaded by fetch-proxies.sh)
#   4. fail2ban is running and jails are active
#   5. fail2ban manually ban/unban an IP via ipset
#   6. ipset entry auto-expires (short timeout)

set -euo pipefail

R='\033[0;31m'; G='\033[0;32m'; Y='\033[1;33m'
C='\033[0;36m'; BD='\033[1m'; RS='\033[0m'

PASS=0
FAIL=0

pass() { echo -e "  ${G}${BD}✓ PASS${RS}  $*"; PASS=$((PASS+1)); }
fail() { echo -e "  ${R}${BD}✗ FAIL${RS}  $*"; FAIL=$((FAIL+1)); }
section() { echo -e "\n${BD}${C}── Test $1: $2 ──────────────────────────────────────${RS}"; }
info() { echo -e "  ${Y}ℹ  $*${RS}"; }

echo ""
echo -e "${BD}╔══════════════════════════════════════════════════════════╗"
echo -e "║       ipset + fail2ban — Standalone Test Suite           ║"
echo -e "╚══════════════════════════════════════════════════════════╝${RS}"

# ─────────────────────────────────────────────────────────────
#  Test 1: ipsets exist
# ─────────────────────────────────────────────────────────────
section 1 "ipsets exist"

for setname in ssh-blocklist proxy-blocklist manual-blocklist; do
    if ipset list "$setname" &>/dev/null; then
        pass "${setname} exists"
    else
        fail "${setname} is missing"
    fi
done

# ─────────────────────────────────────────────────────────────
#  Test 2: iptables rules reference ipsets
# ─────────────────────────────────────────────────────────────
section 2 "iptables INPUT rules reference ipsets"

for setname in proxy-blocklist manual-blocklist; do
    if iptables -L INPUT -n | grep -q "$setname"; then
        pass "INPUT has rule for ${setname}"
    else
        fail "No INPUT rule found for ${setname}"
    fi
done

# ─────────────────────────────────────────────────────────────
#  Test 3: manual-blocklist add / remove
# ─────────────────────────────────────────────────────────────
section 3 "manual-blocklist — add and remove an IP"

TEST_IP="10.0.99.99"

info "Adding ${TEST_IP} to manual-blocklist"
ipset add manual-blocklist "$TEST_IP" -exist

if ipset test manual-blocklist "$TEST_IP" 2>/dev/null; then
    pass "${TEST_IP} present in manual-blocklist after add"
else
    fail "${TEST_IP} NOT found after add"
fi

info "Removing ${TEST_IP} from manual-blocklist"
ipset del manual-blocklist "$TEST_IP" 2>/dev/null || true

if ! ipset test manual-blocklist "$TEST_IP" 2>/dev/null; then
    pass "${TEST_IP} absent from manual-blocklist after remove"
else
    fail "${TEST_IP} still present after remove"
fi

# ─────────────────────────────────────────────────────────────
#  Test 4: proxy-blocklist has entries
# ─────────────────────────────────────────────────────────────
section 4 "proxy-blocklist is populated"

PROXY_COUNT=$(ipset list proxy-blocklist -t 2>/dev/null | grep 'Number of entries:' | awk '{print $NF}' || echo 0)
info "proxy-blocklist entry count: ${PROXY_COUNT}"

if [ "${PROXY_COUNT:-0}" -gt 0 ]; then
    pass "proxy-blocklist has ${PROXY_COUNT} entries"
else
    fail "proxy-blocklist is empty — fetch-proxies.sh may not have run"
fi

# ─────────────────────────────────────────────────────────────
#  Test 5: fail2ban is running
# ─────────────────────────────────────────────────────────────
section 5 "fail2ban process is running"

if fail2ban-client ping 2>/dev/null | grep -q "pong"; then
    pass "fail2ban-client ping → pong"
else
    fail "fail2ban not running or not responding"
fi

# ─────────────────────────────────────────────────────────────
#  Test 6: fail2ban sshd jail is active
# ─────────────────────────────────────────────────────────────
section 6 "fail2ban sshd jail is active"

if fail2ban-client status sshd 2>/dev/null | grep -q "Currently banned"; then
    pass "sshd jail is active"
    info "$(fail2ban-client status sshd 2>/dev/null | grep -E 'Currently|Total' | sed 's/^/   /')"
else
    fail "sshd jail not active in fail2ban"
fi

# ─────────────────────────────────────────────────────────────
#  Test 7: manual fail2ban ban / unban via ipset
# ─────────────────────────────────────────────────────────────
section 7 "fail2ban manual ban → ipset → unban"

BAN_IP="10.1.2.3"
info "Banning ${BAN_IP} via fail2ban-client"

if fail2ban-client set sshd banip "$BAN_IP" 2>/dev/null; then
    sleep 1
    if ipset test ssh-blocklist "$BAN_IP" 2>/dev/null; then
        pass "${BAN_IP} present in ssh-blocklist after ban"
    else
        fail "${BAN_IP} NOT in ssh-blocklist after fail2ban ban"
    fi

    info "Unbanning ${BAN_IP}"
    fail2ban-client set sshd unbanip "$BAN_IP" 2>/dev/null || true
    sleep 1

    if ! ipset test ssh-blocklist "$BAN_IP" 2>/dev/null; then
        pass "${BAN_IP} removed from ssh-blocklist after unban"
    else
        fail "${BAN_IP} still in ssh-blocklist after unban"
    fi
else
    fail "fail2ban-client ban command failed"
fi

# ─────────────────────────────────────────────────────────────
#  Test 8: ipset timeout — entry auto-expires
# ─────────────────────────────────────────────────────────────
section 8 "ipset timeout — entry auto-expires after 3 seconds"

EXPIRE_IP="10.5.6.7"

# Create a temp set with timeout support
ipset create test-timeout hash:ip timeout 0 -exist

info "Adding ${EXPIRE_IP} with 3s timeout"
ipset add test-timeout "$EXPIRE_IP" timeout 3 -exist

if ipset test test-timeout "$EXPIRE_IP" 2>/dev/null; then
    pass "${EXPIRE_IP} present immediately after add"
else
    fail "${EXPIRE_IP} not found — add may have failed"
fi

info "Waiting 5 seconds for entry to expire..."
sleep 5

if ! ipset test test-timeout "$EXPIRE_IP" 2>/dev/null; then
    pass "${EXPIRE_IP} expired and is no longer in the set"
else
    fail "${EXPIRE_IP} still present after 5s (timeout not working)"
fi

ipset destroy test-timeout 2>/dev/null || true

# ─────────────────────────────────────────────────────────────
#  Summary
# ─────────────────────────────────────────────────────────────
TOTAL=$((PASS + FAIL))
echo ""
echo -e "${BD}── Summary ──────────────────────────────────────────────────${RS}"
echo -e "  ${G}${BD}${PASS} passed${RS}  /  ${R}${BD}${FAIL} failed${RS}  /  ${TOTAL} total"

if [ "$FAIL" -eq 0 ]; then
    echo -e "\n  ${G}${BD}All ipset + fail2ban checks passed!${RS}"
else
    echo -e "\n  ${Y}Some checks failed — review the output above.${RS}"
    exit 1
fi
echo ""
