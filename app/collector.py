"""
Collector – tails Cowrie's cowrie.json log and normalises each line into an
Event, then writes it to SQLite.

Cowrie emits one JSON object per line (JSONL). We track file position across
iterations so we can tail efficiently without re-reading the whole file.
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
import time

from db import insert_event

logger = logging.getLogger("ghostwall.collector")

COWRIE_LOG_PATH = os.environ.get("COWRIE_LOG_PATH", "/cowrie-logs/cowrie.json")
POLL_INTERVAL = 2.0  # seconds between tail checks


# ---------------------------------------------------------------------------
# Event kind mapping
# Cowrie eventid -> our normalised kind
# ---------------------------------------------------------------------------

EVENTID_MAP: dict[str, str] = {
    "cowrie.login.failed":      "failed_auth",
    "cowrie.login.success":     "login",
    "cowrie.command.input":     "command",
    "cowrie.session.connect":   "connect",
    "cowrie.session.closed":    "disconnect",
    "cowrie.client.version":    "connect",
    "cowrie.session.file_download": "download",
}


def normalise(raw: dict) -> dict | None:
    """Convert a raw Cowrie JSON record into a normalised event dict.

    Returns None if the record is not one we care about.
    """
    eventid = raw.get("eventid", "")
    kind = EVENTID_MAP.get(eventid)
    if kind is None:
        return None

    # Parse timestamp – Cowrie uses ISO-8601 with space separator
    ts_str = raw.get("timestamp", "")
    try:
        from datetime import datetime, timezone
        dt = datetime.fromisoformat(ts_str.replace(" ", "T"))
        ts = dt.timestamp()
    except Exception:
        ts = time.time()

    src_ip = raw.get("src_ip", raw.get("peerIP", "0.0.0.0"))

    meta: dict = {}
    for key in ("username", "password", "input", "session", "version", "url", "outfile"):
        if key in raw:
            meta[key] = raw[key]

    return {"ts": ts, "src_ip": src_ip, "kind": kind, "meta": meta}


# ---------------------------------------------------------------------------
# Tail loop
# ---------------------------------------------------------------------------

async def tail_log() -> None:
    """Continuously tail COWRIE_LOG_PATH and insert new events into SQLite."""
    logger.info("Collector starting. Watching %s", COWRIE_LOG_PATH)

    # Wait until the file exists (Cowrie may start after us)
    while not os.path.exists(COWRIE_LOG_PATH):
        logger.debug("Log file not found yet, waiting…")
        await asyncio.sleep(5)

    pos = 0
    # Seek to end so we only process new events going forward
    try:
        pos = os.path.getsize(COWRIE_LOG_PATH)
    except OSError:
        pass

    while True:
        try:
            current_size = os.path.getsize(COWRIE_LOG_PATH)
        except OSError:
            await asyncio.sleep(POLL_INTERVAL)
            continue

        if current_size < pos:
            # Log rotated
            logger.info("Log file rotated, resetting position.")
            pos = 0

        if current_size > pos:
            with open(COWRIE_LOG_PATH, "r", errors="replace") as fh:
                fh.seek(pos)
                new_data = fh.read()
                pos = fh.tell()

            for line in new_data.splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    raw = json.loads(line)
                except json.JSONDecodeError:
                    logger.warning("Bad JSON line: %s", line[:120])
                    continue

                event = normalise(raw)
                if event:
                    logger.debug("Event: kind=%s src=%s", event["kind"], event["src_ip"])
                    await insert_event(event["ts"], event["src_ip"], event["kind"], event["meta"])

        await asyncio.sleep(POLL_INTERVAL)
