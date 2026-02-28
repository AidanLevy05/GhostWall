"""SSH-specific defense logic for GhostWall."""
from __future__ import annotations

import logging
from . import ban_ip, is_banned, DRY_RUN

logger = logging.getLogger("ghostwall.defense.ssh")


def respond(src_ip: str, event_kind: str, count: int = 0) -> list[str]:
    """
    Decide how to respond to an SSH event from src_ip.

    Returns a list of action strings taken.
    """
    actions: list[str] = []

    if event_kind == "failed_auth" and count >= 5:
        if not is_banned(src_ip):
            msg = ban_ip(src_ip, 120, reason=f"SSH brute-force ({count} attempts)")
            actions.append(msg)
            logger.info("[SSH] auto-banned %s after %d failed auths", src_ip, count)

    return actions


def rate_limit_banner() -> str:
    tag = "[DRY-RUN] " if DRY_RUN else ""
    return f"{tag}SSH: rate limiting to 5 conn/min per IP"
