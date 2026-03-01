#!/usr/bin/env python3
"""GhostWall runtime orchestrator.

Wires together:
- fake SSH front door (fssh) on a public listen port (default: 22)
- packet scanner event stream
- defense engine action evaluation + policy enforcement
"""

from __future__ import annotations

import argparse
import json
import os
import queue
import sys
import time
from typing import Any

import scanner
from Defense_Solutions.engine import build_defense_actions
from Defense_Solutions.fport import fssh


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="GhostWall unified runtime")
    parser.add_argument(
        "interface",
        nargs="?",
        default=os.getenv("GHOSTWALL_INTERFACE", "eth0"),
        help="Network interface for scanner sniffing (example: lo, eth0, wlan0)",
    )
    parser.add_argument(
        "--listen-port",
        type=int,
        default=int(os.getenv("FSSH_LISTEN_PORT", "22")),
        help="Public fake SSH listen port used by fssh",
    )
    parser.add_argument(
        "--real-ssh-port",
        type=int,
        default=int(os.getenv("FSSH_REAL_SSH_PORT", "47832")),
        help="Local real SSH port for whitelisted users",
    )
    parser.add_argument(
        "--cowrie-port",
        type=int,
        default=int(os.getenv("DEFENSE_COWRIE_PORT", "2222")),
        help="Local Cowrie SSH port for non-whitelisted users",
    )
    parser.add_argument(
        "--whitelist",
        default=os.getenv("FSSH_WHITELIST", ""),
        help="Comma-separated source IP whitelist for real SSH routing",
    )
    parser.add_argument(
        "--show-events",
        action="store_true",
        help="Print raw scanner events as JSON",
    )
    return parser.parse_args()


def parse_whitelist(value: str) -> list[str]:
    ips: list[str] = []
    for raw in value.split(","):
        ip = raw.strip()
        if ip:
            ips.append(ip)
    return ips


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


def _fail_bind_help(listen_port: int, exc: OSError) -> int:
    if exc.errno != 98:
        print(f"[main] fssh bind failed on :{listen_port}: {exc}", file=sys.stderr, flush=True)
        return 1

    print(
        (
            f"[main] cannot bind fssh to :{listen_port} (already in use).\n"
            f"Run: sudo ss -ltnp 'sport = :{listen_port}'\n"
            "If sshd owns it, move sshd to another port (for example 47832) "
            "then restart sshd."
        ),
        file=sys.stderr,
        flush=True,
    )
    return 2


def main() -> int:
    args = parse_args()
    whitelist_ips = parse_whitelist(args.whitelist)

    if os.geteuid() != 0:
        print(
            "[main] warning: not running as root. sniffing and low-port binding may fail.",
            file=sys.stderr,
            flush=True,
        )

    # Configure fssh from runtime args/env.
    fssh.LISTEN_PORT = int(args.listen_port)
    fssh.set_port_map(real_port=int(args.real_ssh_port), honeypot_port=int(args.cowrie_port))
    fssh.set_whitelist(whitelist_ips)

    try:
        fssh_server = fssh.start()
    except OSError as exc:
        return _fail_bind_help(int(args.listen_port), exc)

    q: "queue.Queue[dict[str, Any]]" = queue.Queue()
    scanner.start(args.interface, q)

    print(
        (
            f"[main] interface={args.interface} "
            f"listen_port={args.listen_port} "
            f"real_ssh_port={args.real_ssh_port} "
            f"cowrie_port={args.cowrie_port}"
        ),
        flush=True,
    )
    print(f"[main] whitelist={whitelist_ips}", flush=True)
    print(f"[main] DEFENSE_MODE={os.getenv('DEFENSE_MODE', 'detect')}", flush=True)
    print("[main] CTRL+C to stop", flush=True)

    try:
        while True:
            event = q.get()
            if args.show_events:
                print("[event]", json.dumps(event, separators=(",", ":"), sort_keys=True), flush=True)

            actions = build_defense_actions(event)
            for action in actions:
                print("[action]", format_action(action), flush=True)

            time.sleep(0.001)
    except KeyboardInterrupt:
        print("\n[main] shutting down", flush=True)
    finally:
        try:
            fssh_server.close()
        except Exception:
            pass

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
