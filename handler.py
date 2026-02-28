"""
GhostWall Handler – consumes events, scores threats, triggers defenses.

All state lives in AppState (read by the TUI). No database, no file I/O –
events flow directly from Scanner → Handler via asyncio.Queue.
"""
from __future__ import annotations

import asyncio
import logging
import time
from collections import Counter, deque
from dataclasses import dataclass, field

from scanner import Event

logger = logging.getLogger("ghostwall.handler")

# ---------------------------------------------------------------------------
# Scoring configuration
# ---------------------------------------------------------------------------

SCORE_INTERVAL = 5.0   # seconds between recalculations
DECAY_FACTOR   = 0.97  # score decays slowly when threat drops

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

# Ban threshold: this many failed auths in 10 min → auto-ban
BAN_THRESHOLD = 15


# ---------------------------------------------------------------------------
# Shared application state (read by TUI)
# ---------------------------------------------------------------------------

@dataclass
class AppState:
    score: float = 0.0
    level: str = "GREEN"
    metrics: dict = field(default_factory=dict)
    all_events: list = field(default_factory=list)   # append-only, for TUI feed
    top_ips: list = field(default_factory=list)
    top_users: list = field(default_factory=list)
    defense_log: list = field(default_factory=list)  # append-only
    debrief: str = ""
    banned_ips: set = field(default_factory=set)


# ---------------------------------------------------------------------------
# Handler
# ---------------------------------------------------------------------------

class Handler:
    def __init__(self, queue: asyncio.Queue) -> None:
        self._queue = queue
        self._window: deque[Event] = deque()   # sliding 1-hour window for scoring
        self.state = AppState()
        self._last_debrief_score: float = 0.0

    # ------------------------------------------------------------------
    # Scoring helpers
    # ------------------------------------------------------------------

    def _prune(self) -> None:
        cutoff = time.time() - 3600
        while self._window and self._window[0].ts < cutoff:
            self._window.popleft()

    def _compute_metrics(self) -> dict:
        now = time.time()
        w60  = now - 60
        w10m = now - 600
        w1h  = now - 3600

        evs = list(self._window)

        fail_60s  = [e for e in evs if e.kind == "failed_auth" and e.ts >= w60]
        conn_60s  = [e for e in evs if e.kind == "connect"     and e.ts >= w60]
        ips_10m   = {e.src_ip for e in evs if e.ts >= w10m}
        bans_10m  = [e for e in evs if e.kind == "ban"         and e.ts >= w10m]

        ip_counts_1h = Counter(e.src_ip for e in evs if e.ts >= w1h)
        repeat_off   = sum(1 for c in ip_counts_1h.values() if c > 3)

        top_ips   = ip_counts_1h.most_common(10)
        usernames = [
            e.meta.get("username") for e in evs
            if e.ts >= w1h and e.kind == "failed_auth" and e.meta.get("username")
        ]
        top_users = Counter(usernames).most_common(10)

        return {
            "fail_rate":        len(fail_60s),
            "conn_rate":        len(conn_60s),
            "unique_ips":       len(ips_10m),
            "repeat_offenders": repeat_off,
            "ban_events":       len(bans_10m),
            "top_ips":          top_ips,
            "top_users":        top_users,
        }

    def _raw_score(self, metrics: dict) -> float:
        raw = 0.0
        for key, weight in WEIGHTS.items():
            value = float(metrics.get(key, 0))
            raw  += min(value / CAPS[key], 1.0) * weight
        return round(raw * 100, 2)

    def _to_level(self, score: float) -> str:
        for threshold, label in LEVEL_THRESHOLDS:
            if score >= threshold:
                return label
        return "GREEN"

    # ------------------------------------------------------------------
    # Ban logic
    # ------------------------------------------------------------------

    async def _maybe_ban(self, event: Event) -> None:
        ip = event.src_ip
        if ip in self.state.banned_ips:
            return

        cutoff = time.time() - 600
        recent_fails = sum(
            1 for e in self._window
            if e.src_ip == ip and e.kind == "failed_auth" and e.ts >= cutoff
        )
        if recent_fails >= BAN_THRESHOLD:
            await self._ban(ip, event.service)

    async def _ban(self, ip: str, service: str) -> None:
        from Defense_Solutions import get_defense
        msg = await get_defense(service).ban(ip)
        self.state.banned_ips.add(ip)

        # Record the ban as an event so it shows in the scoring window
        ban_ev = Event(
            ts=time.time(), src_ip=ip, port=0,
            service=service, kind="ban",
        )
        self._window.append(ban_ev)
        self.state.all_events.append(ban_ev)
        self.state.defense_log.append(msg)
        logger.info("Banned %s (%s): %s", ip, service, msg)

    # ------------------------------------------------------------------
    # Scoring loop
    # ------------------------------------------------------------------

    async def _scoring_loop(self) -> None:
        while True:
            try:
                self._prune()
                metrics  = self._compute_metrics()
                raw      = self._raw_score(metrics)
                prev     = self.state.score
                score    = round(min(max(raw, prev * DECAY_FACTOR), 100.0), 2)
                level    = self._to_level(score)

                self.state.score     = score
                self.state.level     = level
                self.state.metrics   = {k: v for k, v in metrics.items()
                                        if k not in ("top_ips", "top_users")}
                self.state.top_ips   = metrics["top_ips"]
                self.state.top_users = metrics["top_users"]

                logger.info("Score=%.1f [%s] fail=%d conn=%d ips=%d",
                            score, level,
                            metrics["fail_rate"], metrics["conn_rate"],
                            metrics["unique_ips"])

                # Trigger LLM debrief on first RED crossing
                if score >= 75 and self._last_debrief_score < 75:
                    asyncio.create_task(self._run_debrief())
                self._last_debrief_score = score

            except Exception as exc:
                logger.exception("Scoring loop error: %s", exc)

            await asyncio.sleep(SCORE_INTERVAL)

    async def _run_debrief(self) -> None:
        from LLM_Debrief.analyzer import generate_debrief
        try:
            text = await generate_debrief(self.state)
            self.state.debrief = text
            self.state.defense_log.append(f"[LLM] {text}")
        except Exception as exc:
            logger.warning("LLM debrief failed: %s", exc)

    # ------------------------------------------------------------------
    # Main run loop
    # ------------------------------------------------------------------

    async def run(self) -> None:
        asyncio.create_task(self._scoring_loop())

        while True:
            try:
                event: Event = await asyncio.wait_for(self._queue.get(), timeout=1.0)
                self._window.append(event)
                self.state.all_events.append(event)
                await self._maybe_ban(event)
            except asyncio.TimeoutError:
                pass
            except Exception as exc:
                logger.exception("Handler error: %s", exc)
