"""
Protocol handlers for GhostWall honeypot.

Each handler accepts an asyncio StreamReader/Writer pair, sends a realistic
banner for that protocol, captures credential attempts, and logs events.
"""
from __future__ import annotations

import asyncio
import logging
import time

from db import insert_event

logger = logging.getLogger("ghostwall.handler")

READ_TIMEOUT = 20.0


# ---------------------------------------------------------------------------
# SSH  (port 22)
# ---------------------------------------------------------------------------

async def handle_ssh(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    src_ip = writer.get_extra_info("peername", ("0.0.0.0", 0))[0]
    await insert_event(time.time(), src_ip, "connect", port=22, proto="SSH")
    logger.info("[SSH ] connect from %s", src_ip)

    try:
        # Send realistic OpenSSH banner
        writer.write(b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6\r\n")
        await writer.drain()

        # Read client banner / first packet
        try:
            data = await asyncio.wait_for(reader.read(512), timeout=READ_TIMEOUT)
            if data:
                banner = data.decode("utf-8", errors="replace").strip()
                # Any data past banner = client is attempting SSH handshake = auth attempt
                await insert_event(
                    time.time(), src_ip, "failed_auth",
                    port=22, proto="SSH",
                    meta={"client_banner": banner[:200]},
                )
                logger.info("[SSH ] %s attempted auth", src_ip)
        except asyncio.TimeoutError:
            pass

    except Exception as exc:
        logger.debug("[SSH ] %s error: %s", src_ip, exc)
    finally:
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass
        await insert_event(time.time(), src_ip, "disconnect", port=22, proto="SSH")


# ---------------------------------------------------------------------------
# FTP  (port 21)
# ---------------------------------------------------------------------------

async def handle_ftp(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    src_ip = writer.get_extra_info("peername", ("0.0.0.0", 0))[0]
    await insert_event(time.time(), src_ip, "connect", port=21, proto="FTP")
    logger.info("[FTP ] connect from %s", src_ip)

    try:
        writer.write(b"220 (vsFTPd 3.0.5)\r\n")
        await writer.drain()

        username = None
        password = None

        try:
            # Read USER command
            line = await asyncio.wait_for(reader.readline(), timeout=READ_TIMEOUT)
            cmd = line.decode("utf-8", errors="replace").strip()
            if cmd.upper().startswith("USER "):
                username = cmd[5:].strip()
                writer.write(f"331 Please specify the password for {username}.\r\n".encode())
                await writer.drain()

                # Read PASS command
                line = await asyncio.wait_for(reader.readline(), timeout=READ_TIMEOUT)
                cmd = line.decode("utf-8", errors="replace").strip()
                if cmd.upper().startswith("PASS "):
                    password = cmd[5:].strip()

                writer.write(b"530 Login incorrect.\r\n")
                await writer.drain()

                await insert_event(
                    time.time(), src_ip, "failed_auth",
                    port=21, proto="FTP",
                    meta={"username": username, "password": password},
                )
                logger.info("[FTP ] %s tried %s / %s", src_ip, username, password)

        except asyncio.TimeoutError:
            pass

    except Exception as exc:
        logger.debug("[FTP ] %s error: %s", src_ip, exc)
    finally:
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass
        await insert_event(time.time(), src_ip, "disconnect", port=21, proto="FTP")


# ---------------------------------------------------------------------------
# Telnet  (port 23)
# ---------------------------------------------------------------------------

async def handle_telnet(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    src_ip = writer.get_extra_info("peername", ("0.0.0.0", 0))[0]
    await insert_event(time.time(), src_ip, "connect", port=23, proto="Telnet")
    logger.info("[TEL ] connect from %s", src_ip)

    try:
        writer.write(b"\r\nUbuntu 22.04.3 LTS\r\n\r\nlogin: ")
        await writer.drain()

        try:
            line = await asyncio.wait_for(reader.readline(), timeout=READ_TIMEOUT)
            username = line.decode("utf-8", errors="replace").strip()

            writer.write(b"Password: ")
            await writer.drain()

            line = await asyncio.wait_for(reader.readline(), timeout=READ_TIMEOUT)
            password = line.decode("utf-8", errors="replace").strip()

            writer.write(b"\r\nLogin incorrect\r\n")
            await writer.drain()

            await insert_event(
                time.time(), src_ip, "failed_auth",
                port=23, proto="Telnet",
                meta={"username": username, "password": password},
            )
            logger.info("[TEL ] %s tried %s / %s", src_ip, username, password)

        except asyncio.TimeoutError:
            pass

    except Exception as exc:
        logger.debug("[TEL ] %s error: %s", src_ip, exc)
    finally:
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass
        await insert_event(time.time(), src_ip, "disconnect", port=23, proto="Telnet")
