#!/usr/bin/env python3
"""
GhostWall – Attack Simulator
=============================
Makes REAL connections to the GhostWall honeypot ports (22/21/23) so the
scanner picks them up directly via the asyncio queue — no log files, no
Docker exec. The score will rise immediately.

Usage
-----
    python3 simulate_attack.py                  # medium preset
    python3 simulate_attack.py --preset heavy   # → RED
    python3 simulate_attack.py --preset light   # → YELLOW
    python3 simulate_attack.py --host 1.2.3.4   # remote target

Requirements: pip install paramiko
"""
from __future__ import annotations

import argparse
import random
import socket
import sys
import threading
import time

# ---------------------------------------------------------------------------
# Attack payload data
# ---------------------------------------------------------------------------

USERNAMES = [
    "root", "admin", "ubuntu", "pi", "guest", "oracle", "postgres",
    "user", "deploy", "git", "jenkins", "ansible", "ec2-user", "vagrant",
    "test", "ftpuser", "www", "mail", "ftp", "nobody",
]

PASSWORDS = [
    "password", "123456", "admin", "root", "letmein", "qwerty",
    "password123", "welcome", "changeme", "toor", "alpine",
    "raspberry", "12345678", "pass", "1234", "test", "guest",
]

PRESETS = {
    "light":  {"ssh": 10, "ftp": 5,  "telnet": 5,  "ips": 3},
    "medium": {"ssh": 30, "ftp": 15, "telnet": 10, "ips": 6},
    "heavy":  {"ssh": 80, "ftp": 30, "telnet": 20, "ips": 12},
}


# ---------------------------------------------------------------------------
# SSH attack (uses paramiko for a proper handshake)
# ---------------------------------------------------------------------------

def _ssh_attempt(host: str, port: int) -> None:
    try:
        import paramiko
    except ImportError:
        _raw_tcp_attempt(host, port, b"SSH-2.0-GhostWallTest\r\n")
        return

    c = paramiko.SSHClient()
    c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        c.connect(
            host, port=port,
            username=random.choice(USERNAMES),
            password=random.choice(PASSWORDS),
            timeout=5,
            look_for_keys=False,
            allow_agent=False,
            banner_timeout=8,
        )
    except paramiko.AuthenticationException:
        pass   # expected – server always rejects
    except Exception:
        pass
    finally:
        c.close()


# ---------------------------------------------------------------------------
# FTP attack (ftplib is in stdlib)
# ---------------------------------------------------------------------------

def _ftp_attempt(host: str, port: int) -> None:
    import ftplib
    try:
        ftp = ftplib.FTP()
        ftp.connect(host, port, timeout=5)
        ftp.login(random.choice(USERNAMES), random.choice(PASSWORDS))
    except ftplib.all_errors:
        pass
    except Exception:
        pass


# ---------------------------------------------------------------------------
# Telnet attack (raw socket – telnetlib is deprecated)
# ---------------------------------------------------------------------------

def _telnet_attempt(host: str, port: int) -> None:
    try:
        s = socket.create_connection((host, port), timeout=5)
        s.recv(256)                              # eat banner
        s.sendall((random.choice(USERNAMES) + "\n").encode())
        time.sleep(0.2)
        s.recv(256)
        s.sendall((random.choice(PASSWORDS) + "\n").encode())
        time.sleep(0.2)
        s.recv(256)
        s.close()
    except Exception:
        pass


def _raw_tcp_attempt(host: str, port: int, payload: bytes) -> None:
    try:
        s = socket.create_connection((host, port), timeout=5)
        s.sendall(payload)
        time.sleep(0.3)
        s.close()
    except Exception:
        pass


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------

def _run_wave(host: str, cfg: dict, delay: float) -> None:
    tasks: list[tuple] = (
        [(_ssh_attempt,    host, 22)] * cfg["ssh"] +
        [(_ftp_attempt,    host, 21)] * cfg["ftp"] +
        [(_telnet_attempt, host, 23)] * cfg["telnet"]
    )
    random.shuffle(tasks)

    threads: list[threading.Thread] = []
    sent = 0
    for fn, h, p in tasks:
        t = threading.Thread(target=fn, args=(h, p), daemon=True)
        threads.append(t)
        t.start()
        sent += 1
        svc = {22: "SSH", 21: "FTP", 23: "TEL"}[p]
        print(f"  [{sent:>3}] {svc}  → {h}:{p}")
        time.sleep(delay)

    for t in threads:
        t.join(timeout=10)


def main() -> None:
    parser = argparse.ArgumentParser(description="GhostWall attack simulator")
    parser.add_argument("--preset", choices=["light", "medium", "heavy"],
                        default="medium")
    parser.add_argument("--host",  default="127.0.0.1",
                        help="Target host (default: 127.0.0.1)")
    parser.add_argument("--delay", type=float, default=0.1,
                        help="Seconds between attempts (default: 0.1)")
    args = parser.parse_args()

    cfg = PRESETS[args.preset]
    total = cfg["ssh"] + cfg["ftp"] + cfg["telnet"]

    print(f"\n  GhostWall Attack Simulator  [{args.preset.upper()}]")
    print(f"  Target  : {args.host}")
    print(f"  Attacks : {cfg['ssh']} SSH  {cfg['ftp']} FTP  {cfg['telnet']} Telnet  = {total} total")
    print(f"  Delay   : {args.delay}s\n")
    print("  Note: paramiko needed for SSH (pip install paramiko)\n")

    _run_wave(args.host, cfg, args.delay)

    print(f"\n  Done. Watch the TUI — score should climb within ~5 seconds.")


if __name__ == "__main__":
    main()
