#!/usr/bin/env bash
set -euo pipefail

CONTAINER="${COWRIE_CONTAINER:-ghostwall-cowrie}"
TAIL_LINES=200
FOLLOW=1

usage() {
  cat <<'EOF'
Usage: ./watch_cowrie_commands.sh [options]

Streams commands typed by attackers in Cowrie (lines containing "CMD:").

Options:
  -c, --container NAME   Cowrie container name (default: ghostwall-cowrie)
  -n, --lines N          Number of recent log lines to include first (default: 200)
      --no-follow        Show recent command lines and exit
  -h, --help             Show this help
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    -c|--container)
      CONTAINER="${2:-}"
      shift 2
      ;;
    -n|--lines)
      TAIL_LINES="${2:-}"
      shift 2
      ;;
    --no-follow)
      FOLLOW=0
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown option: $1" >&2
      usage
      exit 1
      ;;
  esac
done

if ! [[ "$TAIL_LINES" =~ ^[0-9]+$ ]]; then
  echo "--lines must be a non-negative integer." >&2
  exit 1
fi

if ! command -v docker >/dev/null 2>&1; then
  echo "docker is required but not installed." >&2
  exit 1
fi

if ! running_names="$(docker ps --format '{{.Names}}' 2>/dev/null)"; then
  echo "Cannot access Docker daemon. Run with Docker permissions (or via sudo)." >&2
  exit 1
fi

if ! grep -Fxq "$CONTAINER" <<<"$running_names"; then
  echo "Container '$CONTAINER' is not running. Start Cowrie first, then rerun this script." >&2
  exit 1
fi

echo "Watching Cowrie commands from container '$CONTAINER'..."
echo "Format: <timestamp>  <src_ip>  <command>"
echo

LOG_ARGS=(--tail "$TAIL_LINES")
if [[ "$FOLLOW" -eq 1 ]]; then
  LOG_ARGS=(-f "${LOG_ARGS[@]}")
fi

docker logs "${LOG_ARGS[@]}" "$CONTAINER" 2>&1 | awk '
  /CMD: / {
    ts = $1
    ip = "unknown"
    if (match($0, /\[HoneyPotSSHTransport,[0-9]+,([^]]+)\]/, m)) {
      ip = m[1]
    }
    cmd = $0
    sub(/^.*CMD: /, "", cmd)
    printf "%s  %s  %s\n", ts, ip, cmd
    fflush()
  }
'
