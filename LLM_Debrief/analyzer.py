"""
LLM Debrief – generates a short attack analysis using the Anthropic API.
Only runs when the threat score first crosses RED (75+).
Set ANTHROPIC_API_KEY in the environment to enable.
"""
from __future__ import annotations

import asyncio
import os


async def generate_debrief(state) -> str:
    api_key = os.environ.get("ANTHROPIC_API_KEY", "")
    if not api_key:
        return "Set ANTHROPIC_API_KEY to enable LLM debrief."

    top_ips   = ", ".join(f"{ip}({n})" for ip, n in state.top_ips[:5])
    top_users = ", ".join(f"{u}({n})"  for u, n in state.top_users[:5])

    prompt = (
        f"You are a cybersecurity analyst. Summarize this attack in 2 sentences.\n\n"
        f"Threat score: {state.score:.0f}/100 ({state.level})\n"
        f"Failed auths/min: {state.metrics.get('fail_rate', 0)}\n"
        f"Connections/min:  {state.metrics.get('conn_rate', 0)}\n"
        f"Unique attacker IPs: {state.metrics.get('unique_ips', 0)}\n"
        f"Top IPs: {top_ips or 'none'}\n"
        f"Top usernames tried: {top_users or 'none'}\n"
        f"IPs banned so far: {len(state.banned_ips)}\n\n"
        f"2-sentence debrief (attack type, likely motivation):"
    )

    import anthropic
    client = anthropic.Anthropic(api_key=api_key)

    loop = asyncio.get_event_loop()
    response = await loop.run_in_executor(
        None,
        lambda: client.messages.create(
            model="claude-haiku-4-5-20251001",
            max_tokens=120,
            messages=[{"role": "user", "content": prompt}],
        ),
    )
    return response.content[0].text.strip()
