#!/usr/bin/env bash
export PATH="/usr/sbin:/sbin:/usr/bin:/bin:$PATH"
set -euo pipefail

# ===== User-tunable inputs =====
SERVER_V4="${SERVER_V4:-192.168.0.102}"                 # server IPv4 (nginx)
SERVER_V6="${SERVER_V6:-fd42:4242:4242::102}"           # server IPv6 (ULA)
CLIENT_V6="${CLIENT_V6:-fd42:4242:4242::110/64}"        # client IPv6 ULA to add
IFACE="${IFACE:-enp0s3}"                                # client NIC
DURATION="${DURATION:-2}"                               # pause after traffic
OUTDIR="${1:-client_fw_suite_$(date -u +%Y%m%dT%H%M%SZ)}"

# optional: integrate your netfilter hook module
FWMOD_NAME="${FWMOD_NAME:-firewall_log}"
FWMOD_PATH="${FWMOD_PATH:-$HOME/firewall_log.ko}"
# ===============================

mkdir -p "$OUTDIR"

need() { command -v "$1" >/dev/null 2>&1 || { echo "Missing: $1"; exit 1; }; }
need sudo; need nft; need ip; need tcpdump; need curl; need nc; need ping

log() { echo "[*] $*" | tee -a "$OUTDIR/run.log"; }

sudo -v

# ---- Baseline snapshot (to restore later) ----
BASE_RULESET_FILE="$OUTDIR/_baseline_ruleset.nft"
save_baseline_ruleset() {
  # Save in a form we can restore
  sudo nft -s list ruleset > "$BASE_RULESET_FILE" 2>/dev/null || true
  log "Baseline ruleset saved to $BASE_RULESET_FILE"
}

restore_baseline_ruleset() {
  log "Restoring baseline nft ruleset"
  if [[ -s "$BASE_RULESET_FILE" ]]; then
    sudo nft flush ruleset || true
    sudo nft -f "$BASE_RULESET_FILE" || true
  else
    # If baseline snapshot failed, at least flush our temp rules
    sudo nft flush ruleset || true
  fi
}

cleanup_on_exit() {
  restore_baseline_ruleset
  # best-effort: stop captures if any were left running
  sudo pkill tcpdump 2>/dev/null || true
  sudo pkill -f "dmesg -w" 2>/dev/null || true
}
trap cleanup_on_exit EXIT

save_baseline_ruleset

# --- Ensure client IPv6 address (idempotent) ---
if ! ip -6 addr show dev "$IFACE" | grep -q "${CLIENT_V6%%/*}"; then
  log "Adding client IPv6 address $CLIENT_V6 to $IFACE"
  sudo ip -6 addr add "$CLIENT_V6" dev "$IFACE" || true
else
  log "Client IPv6 address already present on $IFACE"
fi

# --- Server IPv6 reachability check ---
V6_REACHABLE=0
if ping -6 -c 1 -W 1 "$SERVER_V6" >/dev/null 2>&1; then
  V6_REACHABLE=1
  log "IPv6 reachability to server OK ($SERVER_V6)"
else
  log "IPv6 reachability to server FAILED ($SERVER_V6). IPv6 tests may fail."
fi

# --- Optional: ensure your module is loaded ---
ensure_fwmod_loaded() {
  if lsmod | grep -q "^${FWMOD_NAME}\b"; then
    log "Kernel module ${FWMOD_NAME} already loaded"
    return
  fi
  if [[ -f "$FWMOD_PATH" ]]; then
    log "Loading kernel module from $FWMOD_PATH"
    sudo insmod "$FWMOD_PATH" || true
  else
    log "Module not found at $FWMOD_PATH; trying modprobe ${FWMOD_NAME}"
    sudo modprobe "$FWMOD_NAME" || true
  fi
}
ensure_fwmod_loaded

# --- Capture helpers ---
start_capture() {
  local tag="$1"
  sudo dmesg -C || true
  sudo sh -c "dmesg -w > '$OUTDIR/$tag.dmesg.log'" & echo $! > "$OUTDIR/$tag.dmesg.pid"
  sudo sh -c "tcpdump -i any -nn -s0 -w '$OUTDIR/$tag.pcap' host '$SERVER_V4' or host '$SERVER_V6' >/dev/null 2>&1" & echo $! > "$OUTDIR/$tag.tcpdump.pid"
}

stop_capture() {
  local tag="$1"
  sudo kill "$(cat "$OUTDIR/$tag.tcpdump.pid")" 2>/dev/null || true
  sudo kill "$(cat "$OUTDIR/$tag.dmesg.pid")" 2>/dev/null || true
  sleep 1
  grep '\[fwlog\]' "$OUTDIR/$tag.dmesg.log" > "$OUTDIR/$tag.fwlog_only.log" 2>/dev/null || true
}

snapshot_ruleset() {
  local name="$1"
  sudo nft -s list ruleset > "$OUTDIR/$name.ruleset.txt" 2>/dev/null || true
}

snapshot_chain() {
  local name="$1"
  sudo nft -a list chain inet fw out > "$OUTDIR/$name.chain.txt" 2>/dev/null || true
}

# --- Traffic generator (targeted only to server) ---
run_traffic() {
  local tag="$1"
  : > "$OUTDIR/$tag.traffic.log"
  log "Traffic for $tag -> $OUTDIR/$tag.traffic.log"

  # HTTPS only tests always run; HTTP tests run only in scenarios that include HTTP
  if [[ "${ALLOW_HTTP:-0}" -eq 1 ]]; then
    (curl -4 -m 3 -sS -o /dev/null -w "IPv4 HTTP: %{http_code}\n"  "http://$SERVER_V4/" || echo "IPv4 HTTP: curl_failed") \
      | tee -a "$OUTDIR/$tag.traffic.log"
  else
    echo "IPv4 HTTP: skipped" | tee -a "$OUTDIR/$tag.traffic.log"
  fi

  (curl -4 -k -m 4 -sS -o /dev/null -w "IPv4 HTTPS: %{http_code}\n" "https://$SERVER_V4/" || echo "IPv4 HTTPS: curl_failed") \
    | tee -a "$OUTDIR/$tag.traffic.log"

  # UDP generator (always sends; whether it passes is policy)
  echo "udp-9999-$tag" | nc -u -w1 "$SERVER_V4" 9999 >/dev/null 2>&1 || true
  echo "udp-5555-$tag" | nc -u -w1 "$SERVER_V4" 5555 >/dev/null 2>&1 || true
  echo "IPv4 UDP: sent to 9999 and 5555" | tee -a "$OUTDIR/$tag.traffic.log"

  if [[ "$V6_REACHABLE" -eq 1 ]]; then
    if [[ "${ALLOW_HTTP:-0}" -eq 1 ]]; then
      (curl -6 -m 3 -sS -o /dev/null -w "IPv6 HTTP: %{http_code}\n"  "http://[$SERVER_V6]/" || echo "IPv6 HTTP: curl_failed") \
        | tee -a "$OUTDIR/$tag.traffic.log"
    else
      echo "IPv6 HTTP: skipped" | tee -a "$OUTDIR/$tag.traffic.log"
    fi

    (curl -6 -k -m 4 -sS -o /dev/null -w "IPv6 HTTPS: %{http_code}\n" "https://[$SERVER_V6]/" || echo "IPv6 HTTPS: curl_failed") \
      | tee -a "$OUTDIR/$tag.traffic.log"

    echo "udp6-9999-$tag" | nc -6 -u -w1 "$SERVER_V6" 9999 >/dev/null 2>&1 || true
    echo "udp6-5555-$tag" | nc -6 -u -w1 "$SERVER_V6" 5555 >/dev/null 2>&1 || true
    echo "IPv6 UDP: sent to 9999 and 5555" | tee -a "$OUTDIR/$tag.traffic.log"
  else
    echo "IPv6 tests: skipped (no reachability)" | tee -a "$OUTDIR/$tag.traffic.log"
  fi

  sleep "$DURATION"
}

# --- Temporary restrictive firewall (for each scenario) ---
# This is the "restrict everything else" base, but still allows:
# - loopback
# - established/related
# - DNS (so curl by name would work, but we mostly use IPs)
# - ICMP + ICMPv6 (needed for NDP / diagnostics)
fw_temp_restrict_base() {
  sudo nft flush ruleset
  sudo nft add table inet fw
  sudo nft add chain inet fw out '{ type filter hook output priority 0; policy drop; }'

  sudo nft add rule inet fw out oif "lo" counter accept
  sudo nft add rule inet fw out ct state established,related counter accept

  sudo nft add rule inet fw out udp dport 53 counter accept
  sudo nft add rule inet fw out tcp dport 53 counter accept

  sudo nft add rule inet fw out ip protocol icmp counter accept
  sudo nft add rule inet fw out ip6 nexthdr icmpv6 counter accept
}

# --- Scenario rule sets ---
# S1: allow only HTTPS (443) to server v4/v6
apply_s1_only_https() {
  fw_temp_restrict_base
  sudo nft add rule inet fw out ip daddr "$SERVER_V4" tcp dport 443 counter accept
  sudo nft add rule inet fw out ip6 daddr "$SERVER_V6" tcp dport 443 counter accept
}

# S2: allow HTTP+HTTPS (80 and 443) to server v4/v6
apply_s2_tcp_80_443() {
  fw_temp_restrict_base
  sudo nft add rule inet fw out ip daddr "$SERVER_V4" tcp dport 80 counter accept
  sudo nft add rule inet fw out ip daddr "$SERVER_V4" tcp dport 443 counter accept
  sudo nft add rule inet fw out ip6 daddr "$SERVER_V6" tcp dport 80 counter accept
  sudo nft add rule inet fw out ip6 daddr "$SERVER_V6" tcp dport 443 counter accept
}

# S3: allow only UDP/9999 to server v4/v6
apply_s3_udp_9999_only() {
  fw_temp_restrict_base
  sudo nft add rule inet fw out ip daddr "$SERVER_V4" udp dport 9999 counter accept
  sudo nft add rule inet fw out ip6 daddr "$SERVER_V6" udp dport 9999 counter accept
}

# S4: allow only IPv6 to server (80/443), block IPv4 to server implicitly
apply_s4_only_ipv6_http_https() {
  fw_temp_restrict_base
  sudo nft add rule inet fw out ip6 daddr "$SERVER_V6" tcp dport 80 counter accept
  sudo nft add rule inet fw out ip6 daddr "$SERVER_V6" tcp dport 443 counter accept
}

run_case() {
  local tag="$1"
  local fn="$2"
  local allow_http="${3:-0}"

  log "===== $tag ====="

  # Save baseline before we temporarily change things (optional per scenario)
  snapshot_ruleset "$tag.baseline_before"

  # Apply restrictive policy + scenario allow rules
  start_capture "$tag"
  ALLOW_HTTP="$allow_http" $fn

  snapshot_ruleset "$tag.temp_after"
  snapshot_chain "$tag.temp_after"

  run_traffic "$tag"

  snapshot_chain "$tag.temp_posttraffic"
  stop_capture "$tag"

  # Restore baseline immediately after each scenario (your requirement)
  restore_baseline_ruleset
  snapshot_ruleset "$tag.baseline_restored"
}

# --- Run suite ---
run_case "S1_only_https_outbound"     apply_s1_only_https           0
run_case "S2_tcp_80_443_outbound"    apply_s2_tcp_80_443           1
run_case "S3_udp_9999_only_outbound" apply_s3_udp_9999_only        0
run_case "S4_only_ipv6_outbound"     apply_s4_only_ipv6_http_https 0

log "Done. Artifacts in $OUTDIR"
log "Per scenario:"
log "  - *.traffic.log      (what succeeded/failed)"
log "  - *.pcap             (what left the client)"
log "  - *.fwlog_only.log   (your module’s hook-path evidence)"
log "  - *.chain.txt        (nft counters -> which rules matched)"
log "  - *.ruleset.txt      (baseline vs temp rulesets)"

