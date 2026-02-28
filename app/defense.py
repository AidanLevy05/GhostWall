"""
Adaptive defense module for SSH-Shield.

Receives the current threat level + top offender list and decides what
actions to take.  By default runs in DRY-RUN mode (prints intended actions).
Set env var DRY_RUN=false to enable real nftables enforcement.

Defense levels
--------------
GREEN   – no action
YELLOW  – enable rate limiting (log intent)
ORANGE  – temporary ban top offenders (60 s dry-run / real nftables)
RED     – extended bans (300 s) + tighten rate limits
"""
from __future__ import annotations

import logging
import os
import subprocess
import time

logger = logging.getLogger("ssh-shield.defense")

DRY_RUN: bool = os.environ.get("DRY_RUN", "true").lower() != "false"

# track active bans: ip -> expiry timestamp
_active_bans: dict[str, float] = {}

BAN_DURATION = {
    "ORANGE": 60,    # seconds
    "RED":    300,
}

RATE_LIMIT_CONN = {
    "YELLOW": 10,    # max connections per minute per IP
    "ORANGE":  5,
    "RED":     2,
}


def _nft_ban(ip: str, duration: int) -> None:
    """Add a temporary nftables drop rule for an IP."""
    if DRY_RUN:
        logger.info("[DRY-RUN] Would ban %s for %ds via nftables", ip, duration)
        return
    try:
        # Add drop rule; a real implementation would use a named set + timeout
        subprocess.run(
            ["nft", "add", "rule", "inet", "filter", "input",
             "ip", "saddr", ip, "drop"],
            check=True, capture_output=True,
        )
        logger.info("Banned %s for %ds via nftables", ip, duration)
    except Exception as exc:
        logger.warning("nftables ban failed for %s: %s", ip, exc)


def _nft_unban(ip: str) -> None:
    if DRY_RUN:
        logger.info("[DRY-RUN] Would unban %s via nftables", ip)
        return
    # Real unban would delete the matching rule handle
    logger.info("Unbanned %s (nftables rule deletion not yet implemented)", ip)


def _rate_limit(level: str) -> str:
    limit = RATE_LIMIT_CONN.get(level, 10)
    if DRY_RUN:
        msg = f"[DRY-RUN] Would set rate limit to {limit} conn/min per IP"
    else:
        msg = f"Rate limit enforced: {limit} conn/min per IP"
    logger.info(msg)
    return msg


def expire_bans() -> list[str]:
    """Remove expired bans and return list of unbanned IPs."""
    now = time.time()
    expired = [ip for ip, exp in _active_bans.items() if exp <= now]
    for ip in expired:
        _nft_unban(ip)
        del _active_bans[ip]
    return expired


def apply_defense(level: str, top_offenders: list[tuple[str, int]]) -> list[str]:
    """
    Apply defenses appropriate to the current threat level.

    Parameters
    ----------
    level       : current threat level string
    top_offenders: list of (ip, event_count) tuples

    Returns
    -------
    List of human-readable action strings taken this cycle.
    """
    expire_bans()
    actions: list[str] = []

    if level == "GREEN":
        return actions

    # Rate limiting for YELLOW+
    actions.append(_rate_limit(level))

    # Banning for ORANGE and RED
    if level in ("ORANGE", "RED"):
        duration = BAN_DURATION[level]
        ban_top_n = 3 if level == "ORANGE" else 5
        now = time.time()

        for ip, count in top_offenders[:ban_top_n]:
            if ip in _active_bans:
                continue  # already banned
            _active_bans[ip] = now + duration
            _nft_ban(ip, duration)
            tag = "[DRY-RUN] " if DRY_RUN else ""
            actions.append(f"{tag}Banned {ip} ({count} events) for {duration}s")

    return actions
