#!/usr/bin/env bash
set -euo pipefail

IFACE="${GHOSTWALL_INTERFACE:-wlp0s20f3}"
FORCE_HONEYPOT="${FSSH_FORCE_HONEYPOT:-172.20.10.3}"
STATIC_WHITELIST="${FSSH_STATIC_WHITELIST:-172.20.10.3,127.0.0.1,172.20.10.4}"

CURRENT_IP="$(
  ip -4 -o addr show dev "$IFACE" scope global \
    | awk '{split($4,a,"/"); print a[1]; exit}'
)"

WHITELIST="$STATIC_WHITELIST"
if [[ -n "$CURRENT_IP" ]]; then
  WHITELIST="${WHITELIST},${CURRENT_IP}"
fi

echo "[run.sh] interface=$IFACE current_ip=${CURRENT_IP:-none} whitelist=$WHITELIST force_honeypot=$FORCE_HONEYPOT"

exec sudo \
  DEFENSE_MODE=auto-block \
  DEFENSE_FIREWALL_BACKEND=nftables \
  FSSH_WHITELIST="$WHITELIST" \
  FSSH_FORCE_HONEYPOT="$FORCE_HONEYPOT" \
  venv/bin/python3 TUI/tui.py \
    --interface "$IFACE" \
    --listen-port 22 \
    --real-ssh-port 47832 \
    --cowrie-port 2222 \
    --reset-blacklist
