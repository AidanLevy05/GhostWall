"""
Threat scoring engine for GhostWall.

Computes a live Threat Score (0-100) from recent DB events.

Score fix: caps lowered so real traffic registers immediately.
Events now come directly from scanner (not Cowrie log), so DB
is always populated when connections hit ports 22/21/23.

Levels
------
  GREEN   0-25
  YELLOW  26-50
  ORANGE  51-74
  RED     75-100

Weights (sum to 1.0)
--------------------
  fail_rate        0.45  - failed auth events per 60s   (cap 10)
  conn_rate        0.25  - connection events per 60s    (cap 10)
  unique_ips       0.20  - unique IPs in last 10 min    (cap  5)
  repeat_offenders 0.10  - IPs seen >2x in last hour   (cap  3)
"""
from __future__ import annotations

import asyncio
import json
import logging
import time
from collections import Counter
from dataclasses import dataclass, field

import db

logger = logging.getLogger("ghostwall.scoring")

SCORE_INTERVAL = 3.0
DECAY_FACTOR   = 0.95

CAPS = {
    "fail_rate":        10.0,
    "conn_rate":        10.0,
    "unique_ips":        5.0,
    "repeat_offenders":  3.0,
}

WEIGHTS = {
    "fail_rate":        0.45,
    "conn_rate":        0.25,
    "unique_ips":       0.20,
    "repeat_offenders": 0.10,
}

LEVEL_THRESHOLDS = [
    (75, "RED"),
    (51, "ORANGE"),
    (26, "YELLOW"),
    (0,  "GREEN"),
]


@dataclass
class ThreatState:
    score: float = 0.0
    level: str = "GREEN"
    metrics: dict = field(default_factory=dict)
    top_ips: list[tuple[str, int]] = field(default_factory=list)
    top_users: list[tuple[str, int]] = field(default_factory=list)
    actions: list[str] = field(default_factory=list)
    total_events: int = 0


_state = ThreatState()


def get_state() -> ThreatState:
    return _state


def _score_to_level(score: float) -> str:
    for threshold, label in LEVEL_THRESHOLDS:
        if score >= threshold:
            return label
    return "GREEN"


def _compute_metrics(events: list[dict]) -> dict:
    now  = time.time()
    w60  = now - 60
    w10m = now - 600
    w1h  = now - 3600

    fail_events = [e for e in events if e["kind"] == "failed_auth" and e["ts"] >= w60]
    conn_events = [e for e in events if e["kind"] == "connect"     and e["ts"] >= w60]
    ips_10m     = {e["src_ip"] for e in events if e["ts"] >= w10m}

    ip_counts_1h = Counter(e["src_ip"] for e in events if e["ts"] >= w1h)
    repeat_off   = sum(1 for c in ip_counts_1h.values() if c > 2)
    top_ips      = ip_counts_1h.most_common(10)

    usernames = []
    for e in events:
        if e["ts"] >= w1h and e["kind"] == "failed_auth":
            try:
                meta = json.loads(e["meta"]) if isinstance(e["meta"], str) else e["meta"]
                u = meta.get("username")
                if u:
                    usernames.append(u)
            except Exception:
                pass
    top_users = Counter(usernames).most_common(10)

    return {
        "fail_rate":        len(fail_events),
        "conn_rate":        len(conn_events),
        "unique_ips":       len(ips_10m),
        "repeat_offenders": repeat_off,
        "top_ips":          top_ips,
        "top_users":        top_users,
    }


def _compute_raw_score(metrics: dict) -> float:
    raw = 0.0
    for key, weight in WEIGHTS.items():
        value      = float(metrics.get(key, 0))
        cap        = CAPS[key]
        normalised = min(value / cap, 1.0)
        raw       += normalised * weight
    return round(raw * 100, 2)


async def scoring_loop() -> None:
    global _state
    logger.info("Scoring loop started (interval=%.1fs)", SCORE_INTERVAL)

    while True:
        try:
            since  = time.time() - 3600
            events = await db.fetch_events_since(since)

            metrics = _compute_metrics(events)
            raw     = _compute_raw_score(metrics)

            prev  = _state.score
            score = max(raw, prev * DECAY_FACTOR)
            score = round(min(score, 100.0), 2)
            level = _score_to_level(score)

            _state.score        = score
            _state.level        = level
            _state.top_ips      = metrics.pop("top_ips", [])
            _state.top_users    = metrics.pop("top_users", [])
            _state.metrics      = metrics
            _state.total_events = len(events)

            logger.debug(
                "Score=%.1f [%s] fail=%d conn=%d uniq=%d",
                score, level,
                metrics["fail_rate"], metrics["conn_rate"], metrics["unique_ips"],
            )

        except Exception:
            logger.exception("Scoring loop error")

        await asyncio.sleep(SCORE_INTERVAL)
