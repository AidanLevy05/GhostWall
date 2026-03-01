"""HTTP defense module for web-targeted traffic."""

from __future__ import annotations

from collections import defaultdict, deque
from typing import Any

from Defense_Solutions.common import CooldownGate, make_action, normalize_event


class HTTPDefense:
    WEB_PORTS = {80, 443, 8080, 8443}
    WINDOW_SECONDS = 60
    PROBE_THRESHOLD = 30
    RATE_LIMIT_SECONDS = 15 * 60

    def __init__(self) -> None:
        self._hits: dict[str, deque[float]] = defaultdict(deque)
        self._cooldown = CooldownGate(cooldown_seconds=20)

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

        if event_type == "connect.attempt" and port in self.WEB_PORTS:
            count = self._record_hit(src_ip, now)
            if self._cooldown.allow(f"http.observe:{src_ip}", now):
                actions.append(
                    make_action(
                        source="http",
                        severity="low" if count < self.PROBE_THRESHOLD else "high",
                        summary=f"HTTP/S probe from {src_ip} on port {port} ({count}/{self.WINDOW_SECONDS}s).",
                        src_ip=src_ip,
                        event_type=event_type,
                        commands=["review reverse-proxy access logs for URI spray/signature patterns"],
                        confidence=0.55 if count < self.PROBE_THRESHOLD else 0.85,
                        tags=["http", "probe"],
                    )
                )

            if count >= self.PROBE_THRESHOLD and self._cooldown.allow(f"http.ratelimit:{src_ip}", now):
                actions.append(
                    make_action(
                        source="http",
                        severity="high",
                        summary=f"HTTP spray threshold exceeded for {src_ip} ({count}/{self.WINDOW_SECONDS}s); apply rate limit.",
                        src_ip=src_ip,
                        event_type=event_type,
                        commands=[
                            "enable temporary strict rate limiting on ingress",
                            "capture source IP in WAF denylist review queue",
                        ],
                        confidence=0.9,
                        tags=["http", "spray", "ratelimit"],
                        mitigation={
                            "type": "rate_limit_ip",
                            "backend": "nftables",
                            "duration_seconds": self.RATE_LIMIT_SECONDS,
                            "reason": "http_high_rate_probe",
                        },
                    )
                )

        if event_type == "port.sweep":
            if any(p in self.WEB_PORTS for p in ev.ports) and self._cooldown.allow(f"http.sweep:{src_ip}", now):
                actions.append(
                    make_action(
                        source="http",
                        severity="medium",
                        summary=f"Port sweep touching web ports from {src_ip}.",
                        src_ip=src_ip,
                        event_type=event_type,
                        commands=[
                            "enable temporary strict rate limiting on ingress",
                            "capture source IP in WAF denylist review queue",
                        ],
                        confidence=0.8,
                        tags=["http", "sweep"],
                    )
                )

        if event_type == "brute.force" and port in self.WEB_PORTS and self._cooldown.allow(f"http.bruteforce:{src_ip}", now):
            actions.append(
                make_action(
                    source="http",
                    severity="high",
                    summary=f"High-rate brute-force signature on web port {port} from {src_ip}.",
                    src_ip=src_ip,
                    event_type=event_type,
                    commands=[
                        "rotate or lock targeted account paths",
                        "tighten WAF challenge policy for source cohort",
                    ],
                    confidence=0.9,
                    tags=["http", "bruteforce"],
                )
            )

        return actions
