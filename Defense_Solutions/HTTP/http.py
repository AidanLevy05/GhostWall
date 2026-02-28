"""HTTP defense module for web-targeted traffic."""

from __future__ import annotations

from typing import Any


class HTTPDefense:
    WEB_PORTS = {80, 443, 8080, 8443}

    def evaluate(self, event: dict[str, Any]) -> list[dict[str, Any]]:
        event_type = str(event.get("type", ""))
        src_ip = str(event.get("src_ip", "unknown"))
        port = event.get("port")
        actions: list[dict[str, Any]] = []

        if event_type == "connect.attempt" and port in self.WEB_PORTS:
            actions.append(
                {
                    "source": "http",
                    "severity": "low",
                    "summary": f"HTTP/S connection attempt from {src_ip} on {port}.",
                    "commands": [
                        "review reverse-proxy access logs for URI spray/signature patterns",
                    ],
                }
            )

        if event_type == "port.sweep":
            ports = event.get("ports", [])
            if any(p in self.WEB_PORTS for p in ports if isinstance(p, int)):
                actions.append(
                    {
                        "source": "http",
                        "severity": "medium",
                        "summary": f"Port sweep touching web ports from {src_ip}.",
                        "commands": [
                            "enable temporary strict rate limiting on ingress",
                            "capture source IP in WAF denylist review queue",
                        ],
                    }
                )

        return actions
