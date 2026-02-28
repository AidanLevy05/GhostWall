"""
Base defense class. Subclasses override _do_ban() with service-specific logic.
DRY_RUN=true (default) logs the action without touching iptables.
"""
import asyncio
import logging
import os

logger = logging.getLogger("ghostwall.defense")
DRY_RUN: bool = os.environ.get("DRY_RUN", "true").lower() == "true"


class BaseDefense:
    service: str = "base"

    async def ban(self, ip: str) -> str:
        if DRY_RUN:
            msg = f"[DRY RUN] Would block {ip} on {self.service.upper()}"
            logger.info(msg)
            return msg
        return await self._do_ban(ip)

    async def _do_ban(self, ip: str) -> str:
        return f"Blocked {ip} ({self.service})"
