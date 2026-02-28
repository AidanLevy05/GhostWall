"""SQLite helpers for GhostWall."""
from __future__ import annotations

import json
import os
import aiosqlite

DB_PATH = os.environ.get("DB_PATH", "./ghostwall.db")

CREATE_EVENTS = """
CREATE TABLE IF NOT EXISTS events (
    id     INTEGER PRIMARY KEY AUTOINCREMENT,
    ts     REAL NOT NULL,
    src_ip TEXT NOT NULL,
    kind   TEXT NOT NULL,
    port   INTEGER NOT NULL DEFAULT 0,
    proto  TEXT NOT NULL DEFAULT '',
    meta   TEXT NOT NULL DEFAULT '{}'
);
"""

CREATE_EVENTS_IDX = "CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts);"


async def init_db() -> None:
    async with aiosqlite.connect(DB_PATH) as conn:
        await conn.execute(CREATE_EVENTS)
        await conn.execute(CREATE_EVENTS_IDX)
        await conn.commit()


async def insert_event(
    ts: float,
    src_ip: str,
    kind: str,
    port: int = 0,
    proto: str = "",
    meta: dict | None = None,
) -> None:
    if meta is None:
        meta = {}
    async with aiosqlite.connect(DB_PATH) as conn:
        await conn.execute(
            "INSERT INTO events (ts, src_ip, kind, port, proto, meta) VALUES (?,?,?,?,?,?)",
            (ts, src_ip, kind, port, proto, json.dumps(meta)),
        )
        await conn.commit()


async def fetch_events_since(since_ts: float) -> list[dict]:
    async with aiosqlite.connect(DB_PATH) as conn:
        conn.row_factory = aiosqlite.Row
        async with conn.execute(
            "SELECT * FROM events WHERE ts >= ? ORDER BY ts DESC", (since_ts,)
        ) as cursor:
            rows = await cursor.fetchall()
    return [dict(r) for r in rows]


async def fetch_recent_events(limit: int = 100) -> list[dict]:
    async with aiosqlite.connect(DB_PATH) as conn:
        conn.row_factory = aiosqlite.Row
        async with conn.execute(
            "SELECT * FROM events ORDER BY ts DESC LIMIT ?", (limit,)
        ) as cursor:
            rows = await cursor.fetchall()
    return [dict(r) for r in rows]
