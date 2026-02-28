"""
GhostWall Scanner – honeypot listeners on SSH (22), FTP (21), Telnet (23).

Each accepted connection/auth attempt creates an Event and puts it into the
shared asyncio.Queue consumed by the Handler.
"""
from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import dataclass, field

import asyncssh

logger = logging.getLogger("ghostwall.scanner")


@dataclass
class Event:
    ts: float
    src_ip: str
    port: int
    service: str   # ssh | ftp | telnet
    kind: str      # connect | failed_auth | command | disconnect | ban
    meta: dict = field(default_factory=dict)


# ---------------------------------------------------------------------------
# SSH honeypot
# ---------------------------------------------------------------------------

class _SSHServer(asyncssh.SSHServer):
    """Always rejects auth but records every attempt."""

    def __init__(self, queue: asyncio.Queue) -> None:
        self._queue = queue
        self._ip = "unknown"

    def connection_made(self, conn: asyncssh.SSHServerConnection) -> None:
        peer = conn.get_extra_info("peername")
        self._ip = peer[0] if peer else "unknown"
        self._queue.put_nowait(Event(
            ts=time.time(), src_ip=self._ip,
            port=22, service="ssh", kind="connect",
        ))

    def connection_lost(self, exc: Exception | None) -> None:
        self._queue.put_nowait(Event(
            ts=time.time(), src_ip=self._ip,
            port=22, service="ssh", kind="disconnect",
        ))

    def begin_auth(self, username: str) -> bool:
        return True  # let auth proceed so we can capture credentials

    def password_auth_requested(self, username: str, password: str) -> bool:
        self._queue.put_nowait(Event(
            ts=time.time(), src_ip=self._ip,
            port=22, service="ssh", kind="failed_auth",
            meta={"username": username, "password": password},
        ))
        return False  # always deny

    def public_key_auth_requested(self, username: str, public_key) -> bool:
        self._queue.put_nowait(Event(
            ts=time.time(), src_ip=self._ip,
            port=22, service="ssh", kind="failed_auth",
            meta={"username": username, "auth_type": "pubkey"},
        ))
        return False


# ---------------------------------------------------------------------------
# FTP honeypot
# ---------------------------------------------------------------------------

async def _handle_ftp(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    queue: asyncio.Queue,
) -> None:
    ip = writer.get_extra_info("peername", ("unknown", 0))[0]
    queue.put_nowait(Event(
        ts=time.time(), src_ip=ip, port=21, service="ftp", kind="connect",
    ))
    username = "unknown"
    try:
        writer.write(b"220 FTP Server Ready\r\n")
        await writer.drain()

        while True:
            line = await asyncio.wait_for(reader.readline(), timeout=30.0)
            if not line:
                break
            cmd = line.decode("utf-8", errors="replace").strip()

            if cmd.upper().startswith("USER "):
                username = cmd[5:].strip()
                writer.write(b"331 Password required\r\n")
                await writer.drain()
            elif cmd.upper().startswith("PASS "):
                password = cmd[5:].strip()
                queue.put_nowait(Event(
                    ts=time.time(), src_ip=ip, port=21, service="ftp",
                    kind="failed_auth",
                    meta={"username": username, "password": password},
                ))
                writer.write(b"530 Login incorrect.\r\n")
                await writer.drain()
            elif cmd.upper() == "QUIT":
                writer.write(b"221 Goodbye.\r\n")
                await writer.drain()
                break
            else:
                writer.write(b"530 Please login with USER and PASS.\r\n")
                await writer.drain()

    except (asyncio.TimeoutError, ConnectionResetError, BrokenPipeError):
        pass
    finally:
        queue.put_nowait(Event(
            ts=time.time(), src_ip=ip, port=21, service="ftp", kind="disconnect",
        ))
        try:
            writer.close()
        except Exception:
            pass


# ---------------------------------------------------------------------------
# Telnet honeypot
# ---------------------------------------------------------------------------

async def _handle_telnet(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    queue: asyncio.Queue,
) -> None:
    ip = writer.get_extra_info("peername", ("unknown", 0))[0]
    queue.put_nowait(Event(
        ts=time.time(), src_ip=ip, port=23, service="telnet", kind="connect",
    ))
    try:
        writer.write(b"\r\nGhostWall login: ")
        await writer.drain()

        line = await asyncio.wait_for(reader.readline(), timeout=30.0)
        username = line.decode("utf-8", errors="replace").strip()

        writer.write(b"Password: ")
        await writer.drain()

        line = await asyncio.wait_for(reader.readline(), timeout=30.0)
        password = line.decode("utf-8", errors="replace").strip()

        queue.put_nowait(Event(
            ts=time.time(), src_ip=ip, port=23, service="telnet",
            kind="failed_auth",
            meta={"username": username, "password": password},
        ))
        writer.write(b"\r\nLogin incorrect\r\n\r\n")
        await writer.drain()

    except (asyncio.TimeoutError, ConnectionResetError, BrokenPipeError):
        pass
    finally:
        queue.put_nowait(Event(
            ts=time.time(), src_ip=ip, port=23, service="telnet", kind="disconnect",
        ))
        try:
            writer.close()
        except Exception:
            pass


# ---------------------------------------------------------------------------
# Scanner (starts all three servers)
# ---------------------------------------------------------------------------

class Scanner:
    def __init__(self, queue: asyncio.Queue) -> None:
        self._queue = queue

    async def start(self) -> None:
        logger.info("Generating SSH host key…")
        host_key = asyncssh.generate_private_key("ssh-rsa")
        q = self._queue

        try:
            ssh_server = await asyncssh.create_server(
                lambda: _SSHServer(q),
                host="",
                port=22,
                server_host_keys=[host_key],
                server_version="SSH-2.0-OpenSSH_8.9p1",
            )
        except OSError as exc:
            logger.error("Cannot bind SSH port 22: %s  (try sudo or check sshd)", exc)
            ssh_server = None

        try:
            ftp_server = await asyncio.start_server(
                lambda r, w: _handle_ftp(r, w, q), host="", port=21,
            )
        except OSError as exc:
            logger.error("Cannot bind FTP port 21: %s", exc)
            ftp_server = None

        try:
            telnet_server = await asyncio.start_server(
                lambda r, w: _handle_telnet(r, w, q), host="", port=23,
            )
        except OSError as exc:
            logger.error("Cannot bind Telnet port 23: %s", exc)
            telnet_server = None

        logger.info("Honeypots active on ports 22/21/23")

        servers = [s for s in (ssh_server, ftp_server, telnet_server) if s is not None]
        if not servers:
            logger.error("No ports could be bound. Run with sudo.")
            return

        tasks = []
        if ssh_server:
            tasks.append(asyncio.create_task(ssh_server.serve_forever()))
        if ftp_server:
            tasks.append(asyncio.create_task(ftp_server.serve_forever()))
        if telnet_server:
            tasks.append(asyncio.create_task(telnet_server.serve_forever()))

        await asyncio.gather(*tasks)
