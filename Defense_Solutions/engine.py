"""Defense response dispatcher for GhostWall events."""

from __future__ import annotations

import time
from typing import Any

from Defense_Solutions.FTP.ftp import FTPDefense
from Defense_Solutions.HTTP.http import HTTPDefense
from Defense_Solutions.SSH.ssh import SSHDefense
from Defense_Solutions.common import CooldownGate
from Defense_Solutions.policy import DefensePolicy

_ssh = SSHDefense()
_http = HTTPDefense()
_ftp = FTPDefense()
_engine_gate = CooldownGate(cooldown_seconds=15)
_policy = DefensePolicy()

_VALID_SEVERITY = {"low", "medium", "high", "critical"}


def _normalize_action(action: dict[str, Any], event: dict[str, Any]) -> dict[str, Any]:
    now = float(event.get("timestamp", time.time()))
    src_ip = str(action.get("src_ip", event.get("src_ip", "unknown")))
    event_type = str(action.get("event_type", event.get("type", "unknown")))
    source = str(action.get("source", "unknown"))
    severity = str(action.get("severity", "low")).lower()
    if severity not in _VALID_SEVERITY:
        severity = "low"

    summary = str(action.get("summary", ""))
    commands = action.get("commands", [])
    if not isinstance(commands, list):
        commands = [str(commands)]

    return {
        **action,
        "source": source,
        "severity": severity,
        "summary": summary,
        "commands": [str(cmd) for cmd in commands],
        "src_ip": src_ip,
        "event_type": event_type,
        "created_at": now,
    }


def build_defense_actions(event: dict[str, Any]) -> list[dict[str, Any]]:
    """Route one event through all defense modules and collect actions."""
    actions: list[dict[str, Any]] = []
    event_ts = float(event.get("timestamp", time.time()))
    for module in (_ssh, _http, _ftp):
        for candidate in module.evaluate(event):
            normalized = _normalize_action(candidate, event)
            dedup_key = (
                f"{normalized['source']}|{normalized['severity']}|"
                f"{normalized['src_ip']}|{normalized['event_type']}|{normalized['summary']}"
            )
            if _engine_gate.allow(dedup_key, event_ts):
                normalized["enforcement"] = _policy.apply_mitigation(normalized)
                _policy.log_action(normalized)
                actions.append(normalized)
    return actions
