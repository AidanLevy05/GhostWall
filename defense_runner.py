#!/usr/bin/env python3
"""Run scanner + defense engine without TUI.

Usage:
  sudo .venv/bin/python defense_runner.py lo
  sudo DEFENSE_MODE=auto-block .venv/bin/python defense_runner.py lo
"""

from __future__ import annotations

import argparse
import json
import queue
import time
from typing import Any

import scanner
from Defense_Solutions.engine import build_defense_actions


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="GhostWall scanner+defense runner")
    parser.add_argument("interface", nargs="?", default="eth0", help="network interface (example: lo, eth0)")
    parser.add_argument("--show-events", action="store_true", help="print raw scanner events as JSON")
    return parser.parse_args()


def format_action(action: dict[str, Any]) -> str:
    source = str(action.get("source", "unknown"))
    severity = str(action.get("severity", "low")).upper()
    summary = str(action.get("summary", ""))
    enforcement = action.get("enforcement", {})
    if isinstance(enforcement, dict):
        applied = enforcement.get("applied")
        reason = enforcement.get("reason", "ok" if applied else "none")
        enforce_text = f"enforcement(applied={applied}, reason={reason})"
    else:
        enforce_text = "enforcement(unknown)"
    return f"[{severity}] {source}: {summary} | {enforce_text}"


def main() -> int:
    args = parse_args()
    q: "queue.Queue[dict[str, Any]]" = queue.Queue()
    scanner.start(args.interface, q)

    print(f"[runner] interface={args.interface}")
    print("[runner] CTRL+C to stop")
    while True:
        event = q.get()
        if args.show_events:
            print("[event]", json.dumps(event, separators=(",", ":"), sort_keys=True))
        actions = build_defense_actions(event)
        for action in actions:
            print("[action]", format_action(action))
        time.sleep(0.001)


if __name__ == "__main__":
    raise SystemExit(main())
