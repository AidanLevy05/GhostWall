"""Common helpers for defense modules."""

from __future__ import annotations

import time
from collections import defaultdict
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class NormalizedEvent:
    event_type: str
    src_ip: str
    port: int | None
    timestamp: float
    ports: tuple[int, ...]
    count: int


def normalize_event(event: dict[str, Any]) -> NormalizedEvent:
    event_type = str(event.get("type", "unknown"))
    src_ip = str(event.get("src_ip", "unknown"))
    timestamp = float(event.get("timestamp", time.time()))

    port_raw = event.get("port")
    port: int | None = None
    if isinstance(port_raw, int):
        port = port_raw
    elif isinstance(port_raw, str) and port_raw.isdigit():
        port = int(port_raw)

    ports_raw = event.get("ports", [])
    ports = tuple(
        sorted(
            {
                int(p)
                for p in ports_raw
                if isinstance(p, int) or (isinstance(p, str) and p.isdigit())
            }
        )
    )
    count_raw = event.get("count", 0)
    count = int(count_raw) if isinstance(count_raw, int) else 0

    return NormalizedEvent(
        event_type=event_type,
        src_ip=src_ip,
        port=port,
        timestamp=timestamp,
        ports=ports,
        count=count,
    )


class CooldownGate:
    """Allow one action per key in each cooldown window."""

    def __init__(self, cooldown_seconds: int) -> None:
        self._cooldown_seconds = cooldown_seconds
        self._last_seen: dict[str, float] = defaultdict(float)

    def allow(self, key: str, now: float) -> bool:
        last = self._last_seen.get(key, 0.0)
        if now - last < self._cooldown_seconds:
            return False
        self._last_seen[key] = now
        return True


def make_action(
    *,
    source: str,
    severity: str,
    summary: str,
    src_ip: str,
    event_type: str,
    commands: list[str],
    confidence: float,
    tags: list[str],
    mitigation: dict[str, Any] | None = None,
) -> dict[str, Any]:
    action = {
        "source": source,
        "severity": severity,
        "summary": summary,
        "src_ip": src_ip,
        "event_type": event_type,
        "commands": commands,
        "confidence": round(max(0.0, min(1.0, confidence)), 2),
        "tags": tags,
        "recommended": True,
    }
    if mitigation:
        action["mitigation"] = mitigation
    return action
