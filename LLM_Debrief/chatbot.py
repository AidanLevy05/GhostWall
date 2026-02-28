"""Local incident debrief helper for GhostWall."""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
from typing import Any


class LocalDebrief:
    def __init__(self) -> None:
        self.backend = os.getenv("GHOSTWALL_LLM_BACKEND", "heuristic").strip().lower()
        self.model = os.getenv("GHOSTWALL_LLM_MODEL", "llama3.2:3b").strip()
        self.timeout_seconds = 10

    def interpret(self, snapshot: dict[str, Any]) -> dict[str, Any]:
        if self.backend == "ollama" and shutil.which("ollama"):
            parsed = self._interpret_with_ollama(snapshot)
            if parsed is not None:
                return parsed
        return self._heuristic(snapshot)

    def _interpret_with_ollama(self, snapshot: dict[str, Any]) -> dict[str, Any] | None:
        prompt = (
            "You are a SOC analyst. Return JSON only with keys: summary, level, actions.\n"
            "level must be one of: low, medium, high, critical.\n"
            "actions must be a list of short actionable strings.\n"
            f"Snapshot: {json.dumps(snapshot, separators=(',', ':'))}"
        )
        try:
            proc = subprocess.run(
                ["ollama", "run", self.model, prompt],
                capture_output=True,
                text=True,
                timeout=self.timeout_seconds,
                check=False,
            )
        except Exception:
            return None

        if proc.returncode != 0:
            return None

        text = (proc.stdout or "").strip()
        if not text:
            return None
        payload = _extract_json_text(text)
        if payload is None:
            return _text_fallback("ollama", text)
        try:
            out = json.loads(payload)
        except json.JSONDecodeError:
            return _text_fallback("ollama", text)

        if not isinstance(out, dict):
            return _text_fallback("ollama", text)
        summary = str(out.get("summary", "No summary"))
        level = str(out.get("level", "medium")).lower()
        actions = out.get("actions", [])
        if not isinstance(actions, list):
            actions = [str(actions)]
        return {
            "backend": f"ollama:{self.model}",
            "summary": summary,
            "level": level,
            "actions": [str(x) for x in actions[:6]],
        }

    def _heuristic(self, snapshot: dict[str, Any]) -> dict[str, Any]:
        avg = float(snapshot.get("avg_threat", 0.0))
        current = int(snapshot.get("current_attacks", 0))
        cowrie_events = int(snapshot.get("cowrie_events", 0))
        top_type = str(snapshot.get("top_event_type", "unknown"))

        level = "low"
        if avg >= 50 or current >= 30:
            level = "high"
        elif avg >= 20 or current >= 10:
            level = "medium"
        if cowrie_events >= 8:
            level = "critical"

        summary = (
            f"Threat={avg:.1f}/99, current attacks={current}, cowrie events={cowrie_events}, "
            f"dominant signal={top_type}."
        )

        actions = [
            "Confirm Cowrie is collecting sessions and auth attempts.",
            "Review top attacking source and affected ports in recent logs.",
            "Escalate to temporary honeypot routing for medium/high activity bands.",
        ]
        if level in {"high", "critical"}:
            actions.append("Apply containment: enforce redirect set and monitor dropped/redirected flows.")
        if top_type == "brute.force":
            actions.append("Prioritize credential abuse triage and account lockout checks.")

        return {
            "backend": "heuristic",
            "summary": summary,
            "level": level,
            "actions": actions[:6],
        }


def _extract_json_text(raw: str) -> str | None:
    raw = raw.strip()
    if raw.startswith("{") and raw.endswith("}"):
        return raw

    fenced = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", raw, flags=re.DOTALL | re.IGNORECASE)
    if fenced:
        return fenced.group(1).strip()

    start = raw.find("{")
    end = raw.rfind("}")
    if start != -1 and end != -1 and end > start:
        return raw[start : end + 1].strip()
    return None


def _text_fallback(backend: str, text: str) -> dict[str, Any]:
    clean = " ".join(text.strip().split())
    level = "medium"
    lower = clean.lower()
    if "critical" in lower:
        level = "critical"
    elif "high" in lower:
        level = "high"
    elif "low" in lower:
        level = "low"

    actions: list[str] = []
    for line in text.splitlines():
        stripped = line.strip(" -*\t")
        if stripped and len(stripped) > 8:
            actions.append(stripped)
        if len(actions) >= 4:
            break
    if not actions:
        actions = ["Review recent attack stream and verify Cowrie session telemetry."]

    return {
        "backend": backend,
        "summary": clean[:260] if clean else "Model returned non-structured output.",
        "level": level,
        "actions": actions[:6],
    }
