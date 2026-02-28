"""FTP defense module."""

from __future__ import annotations

from collections import defaultdict, deque
from typing import Any

from Defense_Solutions.common import CooldownGate, make_action, normalize_event


class FTPDefense:
    FTP_PORTS = {20, 21}
    WINDOW_SECONDS = 120
    PROBE_THRESHOLD = 8
    BLOCK_SECONDS = 15 * 60

    def __init__(self) -> None:
        self._hits: dict[str, deque[float]] = defaultdict(deque)
        self._cooldown = CooldownGate(cooldown_seconds=30)

    def _record_hit(self, src_ip: str, now: float) -> int:
        hit_list = self._hits[src_ip]
        hit_list.append(now)
        cutoff = now - self.WINDOW_SECONDS
        while hit_list and hit_list[0] < cutoff:
            hit_list.popleft()
        return len(hit_list)

    def evaluate(self, event: dict[str, Any]) -> list[dict[str, Any]]:
        ev = normalize_event(event)
        event_type = ev.event_type
        src_ip = ev.src_ip
        port = ev.port
        now = ev.timestamp
        actions: list[dict[str, Any]] = []

        if event_type == "connect.attempt" and port in self.FTP_PORTS:
            count = self._record_hit(src_ip, now)
            if self._cooldown.allow(f"ftp.observe:{src_ip}", now):
                actions.append(
                    make_action(
                        source="ftp",
                        severity="medium" if count < self.PROBE_THRESHOLD else "high",
                        summary=f"FTP probe from {src_ip} on port {port} ({count}/{self.WINDOW_SECONDS}s).",
                        src_ip=src_ip,
                        event_type=event_type,
                        commands=[
                            "verify FTP service necessity; disable if unused",
                            "enforce explicit allowlist if service must stay online",
                        ],
                        confidence=0.72 if count < self.PROBE_THRESHOLD else 0.88,
                        tags=["ftp", "probe"],
                    )
                )

            if count >= self.PROBE_THRESHOLD and self._cooldown.allow(f"ftp.spray:{src_ip}", now):
                actions.append(
                    make_action(
                        source="ftp",
                        severity="high",
                        summary=f"Sustained FTP probing from {src_ip}; review for staged brute-force.",
                        src_ip=src_ip,
                        event_type=event_type,
                        commands=[
                            "rotate affected credentials",
                            "block source IP on perimeter after validation",
                        ],
                        confidence=0.9,
                        tags=["ftp", "spray"],
                        mitigation={
                            "type": "block_ip",
                            "backend": "nftables",
                            "duration_seconds": self.BLOCK_SECONDS,
                            "reason": "ftp_sustained_probe",
                        },
                    )
                )

        if event_type == "brute.force" and port in self.FTP_PORTS and self._cooldown.allow(f"ftp.bruteforce:{src_ip}", now):
            actions.append(
                make_action(
                    source="ftp",
                    severity="high",
                    summary=f"Possible FTP brute force from {src_ip}.",
                    src_ip=src_ip,
                    event_type=event_type,
                    commands=[
                        "rotate affected credentials",
                        "increase lockout threshold strictness and block source",
                    ],
                    confidence=0.93,
                    tags=["ftp", "bruteforce"],
                )
            )

        return actions
