"""
Async TCP port listeners for GhostWall.

Binds to ports 22 (SSH), 21 (FTP), and 23 (Telnet).
Requires root or CAP_NET_BIND_SERVICE for ports < 1024.
"""
from __future__ import annotations

import asyncio
import logging

from handler import handle_ssh, handle_ftp, handle_telnet

logger = logging.getLogger("ghostwall.scanner")

LISTENERS: list[tuple[int, object, str]] = [
    (22, handle_ssh,    "SSH"),
    (21, handle_ftp,    "FTP"),
    (23, handle_telnet, "Telnet"),
]


async def start_listeners() -> None:
    servers: list[asyncio.AbstractServer] = []

    for port, handler, name in LISTENERS:
        try:
            server = await asyncio.start_server(handler, "0.0.0.0", port)
            logger.info("[%s] listening on port %d", name, port)
            servers.append(server)
        except PermissionError:
            logger.error(
                "[%s] permission denied on port %d — run as root or: "
                "sudo setcap 'cap_net_bind_service=+ep' $(which python3)",
                name, port,
            )
        except OSError as exc:
            logger.error("[%s] cannot bind port %d: %s", name, port, exc)

    if not servers:
        logger.critical("No ports could be bound — GhostWall scanner is inactive.")
        return

    await asyncio.gather(*(s.serve_forever() for s in servers))
