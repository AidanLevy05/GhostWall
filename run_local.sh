#!/usr/bin/env bash
# run_local.sh — Start the GhostWall backend locally (no Docker required).
#
# Usage:
#   ./run_local.sh
#
# Then in another terminal run the TUI:
#   python3 tui.py
#
# And in another terminal run the attack simulator:
#   python3 simulate_attack.py

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
VENV="$SCRIPT_DIR/.venv"

# Paths for local development
export COWRIE_LOG_PATH="${COWRIE_LOG_PATH:-/tmp/ghostwall/cowrie.json}"
export DB_PATH="${DB_PATH:-/tmp/ghostwall/shield.db}"
export DRY_RUN="${DRY_RUN:-true}"

mkdir -p /tmp/ghostwall

# Create venv and install deps if needed
if [ ! -f "$VENV/bin/uvicorn" ]; then
    echo "  Setting up Python venv..."
    python3 -m venv "$VENV"
    "$VENV/bin/pip" install -q -r "$SCRIPT_DIR/app/requirements.txt"
    echo "  Dependencies installed."
fi

echo "  GhostWall — local backend"
echo "  Log path : $COWRIE_LOG_PATH"
echo "  DB path  : $DB_PATH"
echo "  Dry run  : $DRY_RUN"
echo "  API      : http://localhost:8000"
echo ""
echo "  In another terminal run:  python3 tui.py"
echo "  To simulate an attack:    python3 simulate_attack.py"
echo ""

cd "$SCRIPT_DIR/app"
exec "$VENV/bin/uvicorn" main:app --host 0.0.0.0 --port 8000
