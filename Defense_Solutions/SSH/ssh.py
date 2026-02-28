"""SSH defense module.

Port 22 honeypot is Cowrie. This module converts scanner events into
actionable SSH/Cowrie response steps.
"""

from __future__ import annotations

from collections import defaultdict, deque
from typing import Any

from Defense_Solutions.common import CooldownGate, make_action, normalize_event


class SSHDefense:
    def __init__(self) -> None:
        self._attempts: dict[str, deque[float]] = defaultdict(deque)
        self._window_seconds = 60
        self._burst_threshold = 6
        self._critical_threshold = 12
        self._block_seconds = 15 * 60
        self._cooldown = CooldownGate(cooldown_seconds=25)

    def _prune(self, src_ip: str, now: float) -> None:
        attempts = self._attempts[src_ip]
        cutoff = now - self._window_seconds
        while attempts and attempts[0] < cutoff:
            attempts.popleft()

    def evaluate(self, event: dict[str, Any]) -> list[dict[str, Any]]:
        ev = normalize_event(event)
        event_type = ev.event_type
        src_ip = ev.src_ip
        port = ev.port
        now = ev.timestamp

        actions: list[dict[str, Any]] = []

        if event_type == "connect.attempt" and port == 22:
            self._attempts[src_ip].append(now)
            self._prune(src_ip, now)
            count = len(self._attempts[src_ip])

            if self._cooldown.allow(f"ssh.observe:{src_ip}", now):
                actions.append(
                    make_action(
                        source="ssh/cowrie",
                        severity="low" if count < self._burst_threshold else "high",
                        summary=f"SSH probe from {src_ip} (port 22) observed on Cowrie ingress.",
                        src_ip=src_ip,
                        event_type=event_type,
                        commands=["docker logs --tail 40 ghostwall-cowrie"],
                        confidence=0.6 if count < self._burst_threshold else 0.82,
                        tags=["ssh", "cowrie", "probe"],
                    )
                )

            if count >= self._burst_threshold and self._cooldown.allow(f"ssh.burst:{src_ip}", now):
                actions.append(
                    make_action(
                        source="ssh/cowrie",
                        severity="high",
                        summary=f"Repeated SSH attempts from {src_ip} ({count} in {self._window_seconds}s).",
                        src_ip=src_ip,
                        event_type=event_type,
                        commands=[
                            "docker logs --tail 200 ghostwall-cowrie",
                            "docker exec ghostwall-cowrie tail -n 20 /cowrie/var/log/cowrie/cowrie.json",
                        ],
                        confidence=0.9,
                        tags=["ssh", "cowrie", "burst"],
                    )
                )

            if count >= self._critical_threshold and self._cooldown.allow(f"ssh.critical:{src_ip}", now):
                actions.append(
                    make_action(
                        source="ssh/cowrie",
                        severity="critical",
                        summary=f"SSH spray from {src_ip} crossed block threshold ({count}/{self._window_seconds}s).",
                        src_ip=src_ip,
                        event_type=event_type,
                        commands=[
                            "sudo -n nft list ruleset",
                            "docker logs --tail 200 ghostwall-cowrie",
                        ],
                        confidence=0.98,
                        tags=["ssh", "cowrie", "spray", "candidate-block"],
                        mitigation={
                            "type": "block_ip",
                            "backend": "nftables",
                            "duration_seconds": self._block_seconds,
                            "reason": "ssh_syn_spray",
                        },
                    )
                )

        if event_type == "brute.force" and port == 22 and self._cooldown.allow(f"ssh.bruteforce:{src_ip}", now):
            actions.append(
                make_action(
                    source="ssh/cowrie",
                    severity="critical",
                    summary=f"Possible SSH brute-force from {src_ip}; prioritize Cowrie log triage.",
                    src_ip=src_ip,
                    event_type=event_type,
                    commands=[
                        "docker logs --tail 200 ghostwall-cowrie",
                        "docker exec ghostwall-cowrie tail -n 5 /cowrie/var/log/cowrie/cowrie.json",
                    ],
                    confidence=0.95,
                    tags=["ssh", "cowrie", "bruteforce"],
                )
            )

        return actions
