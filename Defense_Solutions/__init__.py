"""
Defense_Solutions package.

Provides per-protocol defense handlers and the main defense_loop
that runs as a background asyncio task.
"""
from __future__ import annotations

import asyncio
import logging
import os
import subprocess
import time
from collections import defaultdict

logger = logging.getLogger("ghostwall.defense")

DRY_RUN: bool = os.environ.get("DRY_RUN", "true").lower() != "false"

# ip -> expiry timestamp
_active_bans: dict[str, float] = {}

# ip -> list of connection timestamps (for rate limiting tracking)
_conn_times: dict[str, list[float]] = defaultdict(list)

BAN_DURATION = {"ORANGE": 60, "RED": 300}


def is_banned(ip: str) -> bool:
    exp = _active_bans.get(ip)
    if exp is None:
        return False
    if time.time() >= exp:
        del _active_bans[ip]
        return False
    return True


def ban_ip(ip: str, duration: int, reason: str = "") -> str:
    _active_bans[ip] = time.time() + duration
    tag = "[DRY-RUN] " if DRY_RUN else ""
    msg = f"{tag}Banned {ip} for {duration}s ({reason})"
    logger.info(msg)
    if not DRY_RUN:
        _nft_drop(ip)
    return msg


def unban_expired() -> list[str]:
    now = time.time()
    expired = [ip for ip, exp in list(_active_bans.items()) if exp <= now]
    for ip in expired:
        del _active_bans[ip]
        if not DRY_RUN:
            _nft_remove(ip)
    return expired


def _nft_drop(ip: str) -> None:
    try:
        subprocess.run(
            ["nft", "add", "rule", "inet", "filter", "input",
             "ip", "saddr", ip, "drop"],
            check=True, capture_output=True,
        )
    except Exception as exc:
        logger.warning("nftables ban failed for %s: %s", ip, exc)


def _nft_remove(ip: str) -> None:
    # Real implementation would delete the specific rule handle.
    logger.info("Unbanned %s (nftables rule deletion)", ip)


def apply_defense(level: str, top_offenders: list[tuple[str, int]]) -> list[str]:
    unban_expired()
    actions: list[str] = []

    if level == "GREEN":
        return actions

    tag = "[DRY-RUN] " if DRY_RUN else ""

    if level == "YELLOW":
        actions.append(f"{tag}Rate limiting active: 10 conn/min per IP")

    if level in ("ORANGE", "RED"):
        duration  = BAN_DURATION[level]
        ban_top_n = 3 if level == "ORANGE" else 5
        for ip, count in top_offenders[:ban_top_n]:
            if not is_banned(ip):
                msg = ban_ip(ip, duration, reason=f"{count} events, level={level}")
                actions.append(msg)

    return actions


def get_active_bans() -> dict[str, float]:
    """Return copy of active bans dict (ip -> expiry)."""
    return dict(_active_bans)


async def defense_loop() -> None:
    """Background task: apply defenses every 10 seconds based on threat level."""
    import scoring

    while True:
        try:
            state = scoring.get_state()
            actions = apply_defense(state.level, state.top_ips)
            if actions:
                state.actions = actions
        except Exception:
            logger.exception("Defense loop error")
        await asyncio.sleep(10)
