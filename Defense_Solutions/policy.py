"""Runtime policy for defense actions."""

from __future__ import annotations

import ipaddress
import json
import os
import subprocess
import time
from pathlib import Path
from typing import Any


def _root_dir() -> Path:
    return Path(__file__).resolve().parents[1]


class DefensePolicy:
    def __init__(self) -> None:
        self.mode = os.getenv("DEFENSE_MODE", "detect").strip().lower()
        self.backend = os.getenv("DEFENSE_FIREWALL_BACKEND", "nftables").strip().lower()
        log_name = os.getenv("DEFENSE_ACTION_LOG", "defense_actions.jsonl").strip()
        self.log_path = (_root_dir() / log_name).resolve()
        self.command_timeout = 4.0
        self.cowrie_host = os.getenv("DEFENSE_COWRIE_HOST", "127.0.0.1").strip()
        self.cowrie_port = int(os.getenv("DEFENSE_COWRIE_PORT", "2222").strip())

    @property
    def auto_block(self) -> bool:
        return self.mode == "auto-block"

    def log_action(self, action: dict[str, Any]) -> None:
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        payload = dict(action)
        payload["policy_mode"] = self.mode
        with self.log_path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(payload, separators=(",", ":"), sort_keys=True))
            f.write("\n")

    def apply_mitigation(self, action: dict[str, Any]) -> dict[str, Any]:
        mitigation = action.get("mitigation")
        if not isinstance(mitigation, dict):
            return {"applied": False, "reason": "no_mitigation"}
        if not self.auto_block:
            return {"applied": False, "reason": "detect_mode"}

        m_type = str(mitigation.get("type", ""))
        src_ip = str(action.get("src_ip", ""))
        if not _is_ip(src_ip):
            return {"applied": False, "reason": "invalid_ip"}
        if self.backend != "nftables":
            return {"applied": False, "reason": f"unsupported_backend:{self.backend}"}

        if m_type == "block_ip":
            duration = int(mitigation.get("duration_seconds", 900))
            command = _nft_block_ip_command(src_ip, duration)
            return self._run(command)

        if m_type == "redirect_ssh":
            duration = int(mitigation.get("duration_seconds", 900))
            target_host = str(mitigation.get("target_host", self.cowrie_host))
            target_port = int(mitigation.get("target_port", self.cowrie_port))
            prepared = self._ensure_ssh_redirect_infra(target_host=target_host, target_port=target_port)
            if not prepared.get("applied", False):
                return prepared
            command = _nft_add_redirect_source_command(src_ip=src_ip, duration_seconds=duration)
            return self._run(command)

        if m_type == "rate_limit_ip":
            return {"applied": False, "reason": "manual_rate_limit_required"}

        return {"applied": False, "reason": f"unknown_mitigation:{m_type}"}

    def _run(self, command: list[str]) -> dict[str, Any]:
        effective_command = list(command)
        if os.geteuid() != 0 and effective_command and effective_command[0] == "nft":
            effective_command = ["sudo", "-n", *effective_command]

        try:
            proc = subprocess.run(
                effective_command,
                capture_output=True,
                text=True,
                timeout=self.command_timeout,
                check=False,
            )
        except Exception as exc:  # noqa: BLE001
            return {"applied": False, "reason": "exec_error", "error": str(exc), "command": effective_command}

        result = {
            "applied": proc.returncode == 0,
            "returncode": proc.returncode,
            "command": effective_command,
            "stdout": (proc.stdout or "").strip()[:400],
            "stderr": (proc.stderr or "").strip()[:400],
            "ts": time.time(),
        }
        if proc.returncode != 0:
            result["reason"] = "command_failed"
        return result

    def _ensure_ssh_redirect_infra(self, *, target_host: str, target_port: int) -> dict[str, Any]:
        commands = [
            ["nft", "add", "table", "ip", "ghostwall_nat"],
            [
                "nft",
                "add",
                "chain",
                "ip",
                "ghostwall_nat",
                "prerouting",
                "{",
                "type",
                "nat",
                "hook",
                "prerouting",
                "priority",
                "dstnat;",
                "policy",
                "accept;",
                "}",
            ],
            [
                "nft",
                "add",
                "set",
                "ip",
                "ghostwall_nat",
                "ssh_redirect_sources",
                "{",
                "type",
                "ipv4_addr;",
                "flags",
                "timeout;",
                "}",
            ],
            [
                "nft",
                "add",
                "rule",
                "ip",
                "ghostwall_nat",
                "prerouting",
                "ip",
                "saddr",
                "@ssh_redirect_sources",
                "tcp",
                "dport",
                "22",
                "dnat",
                "to",
                f"{target_host}:{target_port}",
            ],
        ]

        for command in commands:
            result = self._run(command)
            if result.get("applied"):
                continue
            err = str(result.get("stderr", ""))
            if "File exists" in err:
                continue
            result["reason"] = "infra_setup_failed"
            return result

        return {"applied": True, "reason": "infra_ready"}


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def _nft_block_ip_command(src_ip: str, duration_seconds: int) -> list[str]:
    timeout = max(60, int(duration_seconds))
    # Requires an existing nft set:
    #   table inet filter
    #   set ghostwall_blocklist { type ipv4_addr; flags timeout; }
    base = ["nft", "add", "element", "inet", "filter", "ghostwall_blocklist", "{", f"{src_ip}", "timeout", f"{timeout}s", "}"]
    if os.geteuid() == 0:
        return base
    return ["sudo", "-n", *base]


def _nft_add_redirect_source_command(src_ip: str, duration_seconds: int) -> list[str]:
    timeout = max(60, int(duration_seconds))
    base = [
        "nft",
        "add",
        "element",
        "ip",
        "ghostwall_nat",
        "ssh_redirect_sources",
        "{",
        f"{src_ip}",
        "timeout",
        f"{timeout}s",
        "}",
    ]
    if os.geteuid() == 0:
        return base
    return ["sudo", "-n", *base]
