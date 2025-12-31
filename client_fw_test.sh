#!/usr/bin/env bash
export PATH="/usr/sbin:/sbin:/usr/bin:/bin:$PATH"
set -euo pipefail

# ===== Inputs =====
SERVER_V4="${SERVER_V4:-192.168.0.102}"
SERVER_V6="${SERVER_V6:-fd42:4242:4242::102}"
CLIENT_V6="${CLIENT_V6:-fd42:4242:4242::110/64}"
IFACE="${IFACE:-enp0s3}"
DURATION="${DURATION:-2}"
OUTDIR="${1:-client_fw_suite_$(date -u +%Y%m%dT%H%M%SZ)}"

# Kernel module control
FWMOD_NAME="${FWMOD_NAME:-firewall_log}"                 # name shown in lsmod
FWMOD_PATH="${FWMOD_PATH:-$HOME/firewall_log.ko}"        # path to .ko for insmod
# ==================

mkdir -p "$OUTDIR"

need() { command -v "$1" >/dev/null 2>&1 || { echo "Missing: $1"; exit 1; }; }
need sudo; need nft; need ip; need tcpdump; need curl; need nc; need ping

log() { echo "[*] $*" | tee -a "$OUTDIR/run.log"; }

sudo -v

ensure_fwmod_loaded() {
  if lsmod | grep -q "^${FWMOD_NAME}\b"; then
    log "Module ${FWMOD_NAME} already loaded"
    return
  fi
  if [[ -f "$FWMOD_PATH" ]]; then
    log "Loading module via insmod: $FWMOD_PATH"
    sudo insmod "$FWMOD_PATH"
  else
    log "Module file not found at $FWMOD_PATH; trying modprobe ${FWMOD_NAME}"
    sudo modprobe "$FWMOD_NAME"
  fi

  # Confirm
  if ! lsmod | grep -q "^${FWMOD_NAME}\b"; then
    log "ERROR: module ${FWMOD_NAME} still not loaded"
    exit 1
  fi
}

# --- Environment snapshot ---
{
  echo "Kernel: $(uname -r)"
  echo "Client IFACE: $IFACE"
  echo "Server IPv4: $SERVER_V4"
  echo "Server IPv6: $SERVER_V6"
  echo "Client IPv6 (to add): $CLIENT_V6"
  echo "nft: $(nft --version 2>/dev/null || true)"
  echo "Module name: $FWMOD_NAME"
  echo "Module path: $FWMOD_PATH"
  echo "Client IPv4 addrs:"
  ip -4 -o addr show dev "$IFACE" || true
  echo "Client IPv6 addrs:"
  ip -6 -o addr show dev "$IFACE" || true
} > "$OUTDIR/env.txt"

# --- Configure client IPv6 ULA (idempotent) ---
if ! ip -6 addr show dev "$IFACE" | grep -q "${CLIENT_V6%%/*}"; then
  log "Adding client IPv6 address $CLIENT_V6 to $IFACE"
  sudo ip -6 addr add "$CLIENT_V6" dev "$IFACE" || true
else
  log "Client IPv6 address already present on $IFACE"
fi

V6_REACHABLE=0
if ping -6 -c 1 -W 1 "$SERVER_V6" >/dev/null 2>&1; then
  V6_REACHABLE=1
  log "IPv6 reachability to server OK ($SERVER_V6)"
else
  log "IPv6 reachability to server FAILED ($SERVER_V6). IPv6 tests may fail."
fi

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

  # Extract only your module’s output (hook-path evidence)
  grep '\[fwlog\]' "$OUTDIR/$tag.dmesg.log" > "$OUTDIR/$tag.fwlog_only.log" || true
}

snapshot_ruleset() {
  local name="$1"
  sudo nft list ruleset > "$OUTDIR/$name.ruleset.txt" 2>/dev/null || true
}

snapshot_chain_counters() {
  local name="$1"
  sudo nft -a list chain inet fw output > "$OUTDIR/$name.chain.txt" 2>/dev/null || true
}

run_traffic() {
  local tag="$1"
  : > "$OUTDIR/$tag.traffic.log"
  log "Traffic for $tag -> $OUTDIR/$tag.traffic.log"

  (curl -4 -m 3 -sS -o /dev/null -w "IPv4 HTTP: %{http_code}\n"  "http://$SERVER_V4/" || echo "IPv4 HTTP: curl_failed") \
    | tee -a "$OUTDIR/$tag.traffic.log"
  (curl -4 -k -m 4 -sS -o /dev/null -w "IPv4 HTTPS: %{http_code}\n" "https://$SERVER_V4/" || echo "IPv4 HTTPS: curl_failed") \
    | tee -a "$OUTDIR/$tag.traffic.log"

  echo "udp-9999-$tag" | nc -u -w1 "$SERVER_V4" 9999 >/dev/null 2>&1 || true
  echo "udp-5555-$tag" | nc -u -w1 "$SERVER_V4" 5555 >/dev/null 2>&1 || true
  echo "IPv4 UDP: sent to 9999 and 5555" | tee -a "$OUTDIR/$tag.traffic.log"

  if [[ "$V6_REACHABLE" -eq 1 ]]; then
    (curl -6 -m 3 -sS -o /dev/null -w "IPv6 HTTP: %{http_code}\n"  "http://[$SERVER_V6]/" || echo "IPv6 HTTP: curl_failed") \
      | tee -a "$OUTDIR/$tag.traffic.log"
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

# --- Firewall rules (stable: no nft log statements) ---
fw_reset() {
  sudo nft flush ruleset
  sudo nft add table inet fw
  sudo nft add chain inet fw output '{ type filter hook output priority 0; policy drop; }'
}

fw_base_allows() {
  sudo nft add rule inet fw output oif "lo" counter accept
  sudo nft add rule inet fw output ct state established,related counter accept
  sudo nft add rule inet fw output udp dport 53 counter accept
  sudo nft add rule inet fw output tcp dport 53 counter accept
  sudo nft add rule inet fw output ip protocol icmp counter accept
  sudo nft add rule inet fw output ip6 nexthdr icmpv6 counter accept
}

apply_s0_baseline() {
  sudo nft flush ruleset
}

apply_s1_only_https() {
  fw_reset; fw_base_allows
  sudo nft add rule inet fw output ip daddr "$SERVER_V4" tcp dport 443 counter accept
  sudo nft add rule inet fw output ip6 daddr "$SERVER_V6" tcp dport 443 counter accept
}

apply_s2_tcp_80_and_443() {
  fw_reset; fw_base_allows
  sudo nft add rule inet fw output ip daddr "$SERVER_V4" tcp dport 80  counter accept
  sudo nft add rule inet fw output ip daddr "$SERVER_V4" tcp dport 443 counter accept
  sudo nft add rule inet fw output ip6 daddr "$SERVER_V6" tcp dport 80  counter accept
  sudo nft add rule inet fw output ip6 daddr "$SERVER_V6" tcp dport 443 counter accept
}

apply_s3_udp_9999_only() {
  fw_reset; fw_base_allows
  sudo nft add rule inet fw output ip daddr "$SERVER_V4" udp dport 9999 counter accept
  sudo nft add rule inet fw output ip6 daddr "$SERVER_V6" udp dport 9999 counter accept
}

apply_s4_only_ipv6_to_server() {
  fw_reset; fw_base_allows
  sudo nft add rule inet fw output ip6 daddr "$SERVER_V6" tcp dport 80  counter accept
  sudo nft add rule inet fw output ip6 daddr "$SERVER_V6" tcp dport 443 counter accept
}

run_case() {
  local tag="$1"
  local fn="$2"

  log "===== $tag ====="
  snapshot_ruleset "$tag.before"

  start_capture "$tag"
  $fn
  snapshot_ruleset "$tag.after"
  snapshot_chain_counters "$tag.after"

  run_traffic "$tag"
  snapshot_chain_counters "$tag.posttraffic"

  stop_capture "$tag"
}

# ---- Execute ----
ensure_fwmod_loaded

run_case "S0_baseline" apply_s0_baseline
run_case "S1_only_https_outbound" apply_s1_only_https
run_case "S2_tcp_80_443_outbound" apply_s2_tcp_80_and_443
run_case "S3_udp_9999_only_outbound" apply_s3_udp_9999_only
run_case "S4_only_ipv6_outbound" apply_s4_only_ipv6_to_server

log "Done. Artifacts in $OUTDIR"
log "Key files per scenario:"
log "  - *.fwlog_only.log   (YOUR MODULE: hook-path traces)"
log "  - *.chain.txt        (nft counters: which rules matched)"
log "  - *.pcap             (wire evidence)"
log "  - *.traffic.log      (curl results)"
