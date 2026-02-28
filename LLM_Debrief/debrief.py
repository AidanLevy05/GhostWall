"""
LLM-assisted debrief of honeypot attack sessions.

Requires ANTHROPIC_API_KEY environment variable.
If not set, returns a built-in text summary instead.
"""
from __future__ import annotations

import json
import logging
import os
import time
from collections import Counter

import db
import scoring

logger = logging.getLogger("ghostwall.debrief")

_last_debrief: str = "No debrief generated yet. Press D to generate."
_last_generated: float = 0.0
_COOLDOWN = 60.0  # seconds between LLM calls


def _build_summary() -> str:
    """Build a plain-text summary of the last hour's events (no LLM)."""
    state = scoring.get_state()
    top_ips = state.top_ips[:5]
    top_users = state.top_users[:5]
    metrics = state.metrics

    lines = [
        "=== GhostWall Attack Summary ===",
        f"Threat Level : {state.level}",
        f"Score        : {state.score:.1f}/100",
        f"Total Events : {state.total_events}",
        "",
        f"Fail rate    : {metrics.get('fail_rate', 0)} /60s",
        f"Conn rate    : {metrics.get('conn_rate', 0)} /60s",
        f"Unique IPs   : {metrics.get('unique_ips', 0)} /10m",
        f"Repeat offnd : {metrics.get('repeat_offenders', 0)} /1h",
        "",
        "Top Attackers:",
    ]
    for ip, count in top_ips:
        lines.append(f"  {ip:<18} {count} events")

    lines += ["", "Top Usernames Tried:"]
    for user, count in top_users:
        lines.append(f"  {user:<20} {count}x")

    from Defense_Solutions import get_active_bans
    bans = get_active_bans()
    if bans:
        lines += ["", "Active Bans:"]
        for ip, exp in bans.items():
            remaining = max(0, int(exp - time.time()))
            lines.append(f"  {ip:<18} {remaining}s remaining")

    return "\n".join(lines)


async def generate_debrief(force: bool = False) -> str:
    """
    Generate an LLM debrief of the current attack session.

    Uses Anthropic Claude if ANTHROPIC_API_KEY is set; otherwise
    returns a formatted text summary.
    """
    global _last_debrief, _last_generated

    now = time.time()
    if not force and (now - _last_generated) < _COOLDOWN:
        return _last_debrief

    api_key = os.environ.get("ANTHROPIC_API_KEY", "")

    if not api_key:
        _last_debrief = _build_summary()
        _last_generated = now
        return _last_debrief

    try:
        import anthropic

        since = now - 3600
        events = await db.fetch_events_since(since)
        state  = scoring.get_state()

        event_sample = events[:40]
        for e in event_sample:
            if isinstance(e.get("meta"), str):
                try:
                    e["meta"] = json.loads(e["meta"])
                except Exception:
                    pass

        prompt = (
            "You are a cybersecurity analyst reviewing honeypot logs.\n\n"
            f"Current threat score: {state.score:.1f}/100 ({state.level})\n"
            f"Metrics: {json.dumps(state.metrics, indent=2)}\n"
            f"Top attacking IPs: {state.top_ips[:5]}\n"
            f"Top usernames tried: {state.top_users[:5]}\n\n"
            "Recent events (sample):\n"
            f"{json.dumps(event_sample, indent=2, default=str)}\n\n"
            "Provide a concise 3-5 sentence security debrief: what is happening, "
            "who is attacking, what are they after, and what should be done."
        )

        client = anthropic.Anthropic(api_key=api_key)
        message = client.messages.create(
            model="claude-opus-4-6",
            max_tokens=512,
            messages=[{"role": "user", "content": prompt}],
        )
        _last_debrief = message.content[0].text
        _last_generated = now
        logger.info("LLM debrief generated successfully.")

    except ImportError:
        logger.warning("anthropic package not installed; using built-in summary.")
        _last_debrief = _build_summary()
        _last_generated = now
    except Exception as exc:
        logger.error("LLM debrief failed: %s", exc)
        _last_debrief = _build_summary()
        _last_generated = now

    return _last_debrief


def get_last_debrief() -> str:
    return _last_debrief
