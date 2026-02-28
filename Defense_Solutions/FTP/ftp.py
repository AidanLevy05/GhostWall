"""FTP defense module."""

from __future__ import annotations

from typing import Any


class FTPDefense:
    FTP_PORTS = {20, 21}

    def evaluate(self, event: dict[str, Any]) -> list[dict[str, Any]]:
        event_type = str(event.get("type", ""))
        src_ip = str(event.get("src_ip", "unknown"))
        port = event.get("port")
        actions: list[dict[str, Any]] = []

        if event_type == "connect.attempt" and port in self.FTP_PORTS:
            actions.append(
                {
                    "source": "ftp",
                    "severity": "medium",
                    "summary": f"FTP probe from {src_ip} on port {port}.",
                    "commands": [
                        "verify FTP service necessity; disable if unused",
                        "enforce explicit allowlist if service must stay online",
                    ],
                }
            )

        if event_type == "brute.force" and port in self.FTP_PORTS:
            actions.append(
                {
                    "source": "ftp",
                    "severity": "high",
                    "summary": f"Possible FTP brute force from {src_ip}.",
                    "commands": [
                        "rotate affected credentials",
                        "increase lockout threshold strictness and block source",
                    ],
                }
            )

        return actions
