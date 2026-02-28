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

# Paths for local development
export COWRIE_LOG_PATH="${COWRIE_LOG_PATH:-/tmp/ghostwall/cowrie.json}"
export DB_PATH="${DB_PATH:-/tmp/ghostwall/shield.db}"
export DRY_RUN="${DRY_RUN:-true}"

mkdir -p /tmp/ghostwall

echo "  GhostWall — local backend"
echo "  Log path : $COWRIE_LOG_PATH"
echo "  DB path  : $DB_PATH"
echo "  Dry run  : $DRY_RUN"
echo "  API      : http://localhost:8000"
echo ""
echo "  In another terminal run:  python3 tui.py"
echo "  To simulate an attack:    python3 simulate_attack.py"
echo ""

cd "$(dirname "$0")/app"
exec uvicorn main:app --host 0.0.0.0 --port 8000
