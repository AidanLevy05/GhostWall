"""
SQLite database helpers for GhostWall.

Tables
------
events   – one row per normalized Cowrie event
snapshots – periodic threat-score snapshots (optional, for timeline graph)
"""
from __future__ import annotations

import json
import os
import aiosqlite

DB_PATH = os.environ.get("DB_PATH", "/data/shield.db")

# ---------------------------------------------------------------------------
# Schema
# ---------------------------------------------------------------------------

CREATE_EVENTS = """
CREATE TABLE IF NOT EXISTS events (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    ts        REAL    NOT NULL,
    src_ip    TEXT    NOT NULL,
    kind      TEXT    NOT NULL,
    meta      TEXT    NOT NULL DEFAULT '{}'
);
"""

CREATE_EVENTS_IDX = "CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts);"

CREATE_SNAPSHOTS = """
CREATE TABLE IF NOT EXISTS snapshots (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    ts               REAL    NOT NULL,
    score            REAL    NOT NULL,
    level            TEXT    NOT NULL,
    fail_rate        REAL    NOT NULL,
    conn_rate        REAL    NOT NULL,
    unique_ips       INTEGER NOT NULL,
    repeat_offenders INTEGER NOT NULL,
    ban_events       INTEGER NOT NULL
);
"""

CREATE_SNAPSHOTS_IDX = "CREATE INDEX IF NOT EXISTS idx_snapshots_ts ON snapshots(ts);"


async def init_db() -> None:
    """Create tables if they don't exist."""
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute(CREATE_EVENTS)
        await db.execute(CREATE_EVENTS_IDX)
        await db.execute(CREATE_SNAPSHOTS)
        await db.execute(CREATE_SNAPSHOTS_IDX)
        await db.commit()


# ---------------------------------------------------------------------------
# Events
# ---------------------------------------------------------------------------

async def insert_event(ts: float, src_ip: str, kind: str, meta: dict) -> None:
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute(
            "INSERT INTO events (ts, src_ip, kind, meta) VALUES (?, ?, ?, ?)",
            (ts, src_ip, kind, json.dumps(meta)),
        )
        await db.commit()


async def fetch_events_since(since_ts: float) -> list[dict]:
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        async with db.execute(
            "SELECT * FROM events WHERE ts >= ? ORDER BY ts DESC", (since_ts,)
        ) as cursor:
            rows = await cursor.fetchall()
    return [dict(r) for r in rows]


async def fetch_recent_events(limit: int = 200) -> list[dict]:
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        async with db.execute(
            "SELECT * FROM events ORDER BY ts DESC LIMIT ?", (limit,)
        ) as cursor:
            rows = await cursor.fetchall()
    return [dict(r) for r in rows]


# ---------------------------------------------------------------------------
# Snapshots
# ---------------------------------------------------------------------------

async def insert_snapshot(snap: dict) -> None:
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute(
            """INSERT INTO snapshots
               (ts, score, level, fail_rate, conn_rate, unique_ips, repeat_offenders, ban_events)
               VALUES (:ts, :score, :level, :fail_rate, :conn_rate, :unique_ips, :repeat_offenders, :ban_events)""",
            snap,
        )
        await db.commit()


async def fetch_snapshots(limit: int = 300) -> list[dict]:
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        async with db.execute(
            "SELECT * FROM snapshots ORDER BY ts DESC LIMIT ?", (limit,)
        ) as cursor:
            rows = await cursor.fetchall()
    return [dict(r) for r in rows]
