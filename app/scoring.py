"""
Threat scoring engine for GhostWall.

Computes a live Threat Score (0–100) from a metrics window derived from
recent SQLite events, applies decay, and labels the result with a level.

Levels
------
  GREEN   0–25
  YELLOW  26–50
  ORANGE  51–74
  RED     75–100

Weights (must sum to 1.0)
-------------------------
  fail_rate        0.40   – failed auth events per 60 s  (cap 30)
  conn_rate        0.25   – connection events per 60 s   (cap 20)
  unique_ips       0.20   – unique IPs in last 10 min    (cap 15)
  repeat_offenders 0.10   – IPs seen >3× in last hour    (cap 10)
  ban_events       0.05   – ban events in last 10 min    (cap  5)
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

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

SCORE_INTERVAL = 5.0   # seconds between score recalculations
DECAY_FACTOR   = 0.97  # score × decay per interval when below raw score

CAPS = {
    "fail_rate":        30.0,
    "conn_rate":        20.0,
    "unique_ips":       15.0,
    "repeat_offenders": 10.0,
    "ban_events":        5.0,
}

WEIGHTS = {
    "fail_rate":        0.40,
    "conn_rate":        0.25,
    "unique_ips":       0.20,
    "repeat_offenders": 0.10,
    "ban_events":       0.05,
}

LEVEL_THRESHOLDS = [
    (75, "RED"),
    (51, "ORANGE"),
    (26, "YELLOW"),
    (0,  "GREEN"),
]


# ---------------------------------------------------------------------------
# Shared mutable state (in-memory; updated by the scoring loop)
# ---------------------------------------------------------------------------

@dataclass
class ThreatState:
    score: float = 0.0
    level: str = "GREEN"
    metrics: dict = field(default_factory=dict)
    top_ips: list[tuple[str, int]] = field(default_factory=list)
    top_users: list[tuple[str, int]] = field(default_factory=list)
    actions: list[str] = field(default_factory=list)


_state = ThreatState()


def get_state() -> ThreatState:
    return _state


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _score_to_level(score: float) -> str:
    for threshold, label in LEVEL_THRESHOLDS:
        if score >= threshold:
            return label
    return "GREEN"


def _compute_metrics(events: list[dict]) -> dict:
    now = time.time()
    w60  = now - 60
    w10m = now - 600
    w1h  = now - 3600

    fail_events = [e for e in events if e["kind"] == "failed_auth" and e["ts"] >= w60]
    conn_events = [e for e in events if e["kind"] == "connect"     and e["ts"] >= w60]
    ips_10m     = {e["src_ip"] for e in events if e["ts"] >= w10m}
    ban_events  = [e for e in events if e["kind"] == "ban"         and e["ts"] >= w10m]

    # Repeat offenders: IPs with >3 events in last hour
    ip_counts_1h = Counter(e["src_ip"] for e in events if e["ts"] >= w1h)
    repeat_off   = sum(1 for c in ip_counts_1h.values() if c > 3)

    # Top offending IPs (last hour)
    top_ips = ip_counts_1h.most_common(10)

    # Top usernames attempted (last hour)
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
        "fail_rate":        len(fail_events),   # events per last 60 s
        "conn_rate":        len(conn_events),
        "unique_ips":       len(ips_10m),
        "repeat_offenders": repeat_off,
        "ban_events":       len(ban_events),
        "top_ips":          top_ips,
        "top_users":        top_users,
    }


def _compute_raw_score(metrics: dict) -> float:
    raw = 0.0
    for key, weight in WEIGHTS.items():
        value = float(metrics.get(key, 0))
        cap   = CAPS[key]
        normalised = min(value / cap, 1.0)
        raw += normalised * weight
    return round(raw * 100, 2)


def _build_why(metrics: dict) -> str:
    return (
        f"fail {metrics['fail_rate']}/min, "
        f"conn {metrics['conn_rate']}/min, "
        f"uniq IPs {metrics['unique_ips']}/10m, "
        f"bans {metrics['ban_events']}/10m"
    )


# ---------------------------------------------------------------------------
# Scoring loop (background asyncio task)
# ---------------------------------------------------------------------------

async def scoring_loop() -> None:
    """Recalculate threat score every SCORE_INTERVAL seconds."""
    global _state
    logger.info("Scoring loop started (interval=%ss, decay=%.2f)", SCORE_INTERVAL, DECAY_FACTOR)

    while True:
        try:
            # Pull events from the last hour (enough for all windows)
            since = time.time() - 3600
            events = await db.fetch_events_since(since)

            metrics = _compute_metrics(events)
            raw     = _compute_raw_score(metrics)

            # Apply decay: score only drops gradually
            prev = _state.score
            score = max(raw, prev * DECAY_FACTOR)
            score = round(min(score, 100.0), 2)

            level = _score_to_level(score)

            _state.score     = score
            _state.level     = level
            _state.metrics   = metrics
            _state.top_ips   = metrics.pop("top_ips", [])
            _state.top_users = metrics.pop("top_users", [])

            logger.info(
                "Score=%.1f [%s] fail=%d conn=%d uniq_ips=%d",
                score, level,
                metrics["fail_rate"], metrics["conn_rate"], metrics["unique_ips"],
            )

            # Persist snapshot
            snap = {
                "ts":               time.time(),
                "score":            score,
                "level":            level,
                "fail_rate":        metrics["fail_rate"],
                "conn_rate":        metrics["conn_rate"],
                "unique_ips":       metrics["unique_ips"],
                "repeat_offenders": metrics["repeat_offenders"],
                "ban_events":       metrics["ban_events"],
            }
            await db.insert_snapshot(snap)

        except Exception as exc:
            logger.exception("Scoring loop error: %s", exc)

        await asyncio.sleep(SCORE_INTERVAL)
