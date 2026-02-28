"""SSH defense module.

Port 22 honeypot is Cowrie. This module converts scanner events into
actionable SSH/Cowrie response steps.
"""

from __future__ import annotations

import time
from collections import defaultdict, deque
from typing import Any


class SSHDefense:
    def __init__(self) -> None:
        self._attempts: dict[str, deque[float]] = defaultdict(deque)
        self._window_seconds = 90
        self._burst_threshold = 8

    def _prune(self, src_ip: str, now: float) -> None:
        attempts = self._attempts[src_ip]
        cutoff = now - self._window_seconds
        while attempts and attempts[0] < cutoff:
            attempts.popleft()

    def evaluate(self, event: dict[str, Any]) -> list[dict[str, Any]]:
        event_type = str(event.get("type", ""))
        src_ip = str(event.get("src_ip", "unknown"))
        port = event.get("port")
        now = float(event.get("timestamp", time.time()))

        actions: list[dict[str, Any]] = []

        if event_type == "connect.attempt" and port == 22:
            self._attempts[src_ip].append(now)
            self._prune(src_ip, now)
            count = len(self._attempts[src_ip])

            actions.append(
                {
                    "source": "ssh/cowrie",
                    "severity": "low" if count < self._burst_threshold else "high",
                    "summary": f"SSH probe from {src_ip} (port 22) observed by Cowrie path.",
                    "commands": [
                        "docker logs --tail 40 ghostwall-cowrie",
                    ],
                }
            )

            if count >= self._burst_threshold:
                actions.append(
                    {
                        "source": "ssh/cowrie",
                        "severity": "high",
                        "summary": f"Repeated SSH attempts from {src_ip} ({count} in {self._window_seconds}s).",
                        "commands": [
                            "docker logs --tail 200 ghostwall-cowrie",
                            "docker compose restart ghostwall-cowrie",
                        ],
                    }
                )

        if event_type == "brute.force" and port == 22:
            actions.append(
                {
                    "source": "ssh/cowrie",
                    "severity": "critical",
                    "summary": f"Possible SSH brute-force from {src_ip}; prioritize Cowrie log triage.",
                    "commands": [
                        "docker logs --tail 200 ghostwall-cowrie",
                        "docker exec ghostwall-cowrie tail -n 5 /cowrie/var/log/cowrie/cowrie.json",
                    ],
                }
            )

        return actions
