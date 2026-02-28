"""SMTP-specific defense logic for GhostWall (port 25)."""
from __future__ import annotations

import logging
from . import ban_ip, is_banned, DRY_RUN

logger = logging.getLogger("ghostwall.defense.smtp")


def respond(src_ip: str, event_kind: str, count: int = 0) -> list[str]:
    """
    Decide how to respond to an SMTP event from src_ip.

    Returns a list of action strings taken.
    """
    actions: list[str] = []

    if event_kind == "failed_auth" and count >= 4:
        if not is_banned(src_ip):
            msg = ban_ip(src_ip, 120, reason=f"SMTP relay abuse ({count} attempts)")
            actions.append(msg)
            logger.info("[SMTP] auto-banned %s after %d failed auths", src_ip, count)

    return actions


def rate_limit_banner() -> str:
    tag = "[DRY-RUN] " if DRY_RUN else ""
    return f"{tag}SMTP: rate limiting to 2 conn/min per IP"
