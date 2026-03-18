#!/bin/bash
# fetch-proxies.sh — Download public proxy IP lists and load into the proxy-blocklist ipset.
#
# Usage:
#   /fetch-proxies.sh               # fetch all sources, load into ipset
#   /fetch-proxies.sh --dry-run     # show what would be loaded, don't actually load
#   /fetch-proxies.sh --verbose     # print each IP as it is added
#   /fetch-proxies.sh --stats       # show ipset stats after loading
#
# The proxy-blocklist ipset (hash:net) is created if it doesn't exist.
# Each source returns one "IP:PORT" entry per line; the port is stripped.

set -euo pipefail

# ── Flags ─────────────────────────────────────────────────────────────────────
DRY_RUN=false
VERBOSE=false
SHOW_STATS=false

IPSET_NAME="proxy-blocklist"
TMPFILE=$(mktemp /tmp/proxies-XXXXXX.txt)

# ── Colours ───────────────────────────────────────────────────────────────────
R='\033[0;31m'; G='\033[0;32m'; Y='\033[1;33m'
C='\033[0;36m'; BD='\033[1m'; RS='\033[0m'

log()  { echo -e "${C}[PROXY-FETCH]${RS} $*"; }
ok()   { echo -e "${G}[PROXY-FETCH][OK]${RS} $*"; }
warn() { echo -e "${Y}[PROXY-FETCH][WARN]${RS} $*"; }
err()  { echo -e "${R}[PROXY-FETCH][ERR]${RS} $*" >&2; }

for arg in "$@"; do
    case "$arg" in
        --dry-run)  DRY_RUN=true  ;;
        --verbose)  VERBOSE=true  ;;
        --stats)    SHOW_STATS=true ;;
        *) err "Unknown argument: $arg"; exit 1 ;;
    esac
done

cleanup() { rm -f "$TMPFILE"; }
trap cleanup EXIT

# ── Remote sources ─────────────────────────────────────────────────────────────
# Public proxy lists — each returns one "IP:PORT" entry per line.
SOURCES=(
    "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/http.txt"
    "https://raw.githubusercontent.com/clarketm/proxy-list/master/proxy-list-raw.txt"
    "https://raw.githubusercontent.com/ShiftyTR/Proxy-List/master/http.txt"
)

# ── Fallback CIDRs ─────────────────────────────────────────────────────────────
# Used when all remote sources are unreachable (e.g., offline / CI environment).
# These are well-known public proxy / Tor exit-node ranges for demo purposes.
FALLBACK_CIDRS=(
    "185.220.100.0/22"   # Tor exit nodes (torservers.net)
    "104.244.72.0/21"    # Known proxy hosting (AS394711)
    "192.42.116.0/22"    # Tor Project official range
    "199.87.154.0/24"    # Open proxy hosting
    "45.142.212.0/22"    # Datacenter proxy range
    "23.129.64.0/18"     # Tor / proxy hosting
    "51.75.144.0/21"     # OVH cloud proxy hosting
    "103.251.167.0/24"   # Proxy hosting (APNIC)
    "91.108.4.0/22"      # Telegram proxy range (demo)
    "176.10.99.0/24"     # Cached proxy range
)

echo ""
log "Starting proxy list fetch → ${BD}${IPSET_NAME}${RS}"
echo ""

# ── Fetch remote sources ───────────────────────────────────────────────────────
FETCHED_SOURCES=0
for url in "${SOURCES[@]}"; do
    log "Fetching: ${Y}${url}${RS}"
    if curl -fsSL --connect-timeout 10 --max-time 30 "$url" >> "$TMPFILE" 2>/dev/null; then
        lines=$(wc -l < "$TMPFILE")
        ok "Downloaded — running line total: ${lines}"
        FETCHED_SOURCES=$((FETCHED_SOURCES + 1))
    else
        warn "Unreachable: ${url} — skipping"
    fi
done

# ── Extract unique IPs ─────────────────────────────────────────────────────────
# Strips port from "IP:PORT" lines; skips comments and blank lines.
IP_LIST=$(grep -Eo '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' "$TMPFILE" 2>/dev/null | sort -u || true)
IP_COUNT=$(echo "$IP_LIST" | grep -c '[0-9]' 2>/dev/null || true)

USE_FALLBACK=false
if [ "$FETCHED_SOURCES" -eq 0 ] || [ "${IP_COUNT:-0}" -eq 0 ]; then
    warn "No IPs fetched from remote sources — using built-in fallback CIDR list"
    IP_LIST=$(printf '%s\n' "${FALLBACK_CIDRS[@]}")
    IP_COUNT="${#FALLBACK_CIDRS[@]}"
    USE_FALLBACK=true
fi

echo ""
log "Unique entries to load: ${BD}${IP_COUNT}${RS}  (fallback=${USE_FALLBACK})"

# ── Dry-run: just print ────────────────────────────────────────────────────────
if $DRY_RUN; then
    echo ""
    log "Dry-run mode — would load (first 20 shown):"
    echo "$IP_LIST" | head -20 | while read -r entry; do
        echo "  + ${entry}"
    done
    [ "$IP_COUNT" -gt 20 ] && warn "  ... and $((IP_COUNT - 20)) more"
    echo ""
    ok "Dry run complete — no ipset changes made."
    exit 0
fi

# ── Ensure ipset exists ────────────────────────────────────────────────────────
if ! ipset list "$IPSET_NAME" &>/dev/null; then
    log "ipset '${IPSET_NAME}' not found — creating it"
    ipset create "$IPSET_NAME" hash:net maxelem 131072
    ok "Created ipset: ${IPSET_NAME}"
fi

# ── Load entries into ipset ────────────────────────────────────────────────────
ADDED=0
SKIPPED=0

while IFS= read -r entry; do
    [ -z "$entry" ] && continue
    if ipset add "$IPSET_NAME" "$entry" -exist 2>/dev/null; then
        ADDED=$((ADDED + 1))
        $VERBOSE && log "  + ${entry}"
    else
        SKIPPED=$((SKIPPED + 1))
        $VERBOSE && warn "  ✗ ${entry} (invalid CIDR or error)"
    fi
done <<< "$IP_LIST"

echo ""
ok "Loaded ${BD}${ADDED}${RS} entries into ${BD}${IPSET_NAME}${RS} (${SKIPPED} skipped/invalid)"

if $SHOW_STATS; then
    echo ""
    log "ipset stats for ${IPSET_NAME}:"
    ipset list "$IPSET_NAME" -t
fi

echo ""
