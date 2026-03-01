#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SIM="$SCRIPT_DIR/simulate_attack.py"
DRIVER="${GW_TEST_DRIVER:-live}"

usage() {
  cat <<'EOF'
Usage:
  ./test.sh <level> [--live|--sim] [extra simulate_attack args...]

Levels:
  1 | light    -> light attack preset
  2 | medium   -> medium attack preset
  3 | heavy    -> heavy attack preset

Examples:
  ./test.sh 1              # live TCP probes (default)
  ./test.sh 2 --live       # explicit live mode
  ./test.sh 3 --sim        # Cowrie log simulation mode
  ./test.sh heavy --sim --events 200

Notes:
  --live (default): sends real probe traffic from a Docker container to host ports.
  --sim: runs simulate_attack.py presets.
EOF
}

if [[ $# -lt 1 ]]; then
  usage
  exit 1
fi

if [[ ! -f "$SIM" ]]; then
  echo "simulate_attack.py not found at: $SIM" >&2
  exit 1
fi

level_raw="$1"
shift

extra_args=()
while [[ $# -gt 0 ]]; do
  case "$1" in
    --live)
      DRIVER="live"
      shift
      ;;
    --sim|--simulate)
      DRIVER="sim"
      shift
      ;;
    -h|--help|help)
      usage
      exit 0
      ;;
    *)
      extra_args+=("$1")
      shift
      ;;
  esac
done

case "${level_raw,,}" in
  1|light)
    preset="light"
    attempts_default=60
    delay_default=0.03
    ports="22"
    ;;
  2|medium)
    preset="medium"
    attempts_default=220
    delay_default=0.01
    ports="22 80 443"
    ;;
  3|heavy)
    preset="heavy"
    attempts_default=600
    delay_default=0.005
    ports="22 80 443"
    ;;
  -h|--help|help)
    usage
    exit 0
    ;;
  *)
    echo "Invalid level: $level_raw" >&2
    usage
    exit 1
    ;;
esac

if [[ "$DRIVER" == "sim" ]]; then
  echo "[test.sh] driver=sim preset=$preset"
  exec python3 "$SIM" --preset "$preset" "${extra_args[@]}"
fi

if [[ "$DRIVER" != "live" ]]; then
  echo "Unknown driver: $DRIVER" >&2
  usage
  exit 1
fi

if ! command -v docker >/dev/null 2>&1; then
  echo "docker is required for --live mode (or run with --sim)." >&2
  exit 1
fi

if [[ ${#extra_args[@]} -gt 0 ]]; then
  echo "Extra args are only used with --sim mode: ${extra_args[*]}" >&2
  exit 1
fi

attempts="${GW_TEST_ATTEMPTS:-$attempts_default}"
delay="${GW_TEST_DELAY:-$delay_default}"
image="${GW_TEST_IMAGE:-busybox:1.36}"

echo "[test.sh] driver=live preset=$preset attempts=$attempts delay=$delay ports=[$ports]"
echo "[test.sh] sending probes from docker container image=$image"

exec docker run --rm --network bridge "$image" sh -c \
  "H=\$(ip route 2>/dev/null | awk '/default/ {print \$3; exit}');
   if [ -z \"\$H\" ]; then
     H=\$(route -n 2>/dev/null | awk '/^0.0.0.0/ {print \$2; exit}');
   fi;
   if [ -z \"\$H\" ]; then
     echo 'Could not determine host gateway inside container.' >&2;
     exit 2;
   fi;
   i=0;
   while [ \"\$i\" -lt \"$attempts\" ]; do
     for p in $ports; do
       (nc -w1 \"\$H\" \"\$p\" </dev/null >/dev/null 2>&1 || true) &
     done;
     i=\$((i+1));
     sleep \"$delay\";
   done;
   wait"
