"""Telnet-specific defense logic for GhostWall."""
from __future__ import annotations

import logging
from . import ban_ip, is_banned, DRY_RUN

logger = logging.getLogger("ghostwall.defense.telnet")


def respond(src_ip: str, event_kind: str, count: int = 0) -> list[str]:
    """
    Decide how to respond to a Telnet event from src_ip.

    Returns a list of action strings taken.
    """
    actions: list[str] = []

    # Telnet is almost never legitimate — ban after 2 attempts
    if event_kind == "failed_auth" and count >= 2:
        if not is_banned(src_ip):
            msg = ban_ip(src_ip, 180, reason=f"Telnet brute-force ({count} attempts)")
            actions.append(msg)
            logger.info("[Telnet] auto-banned %s after %d failed auths", src_ip, count)

    return actions


def rate_limit_banner() -> str:
    tag = "[DRY-RUN] " if DRY_RUN else ""
    return f"{tag}Telnet: rate limiting to 1 conn/min per IP"
