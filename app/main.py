"""
GhostWall – FastAPI application entry point.

Starts two background tasks on startup:
  1. collector.tail_log()  – tails Cowrie JSON log → SQLite
  2. scoring.scoring_loop() – recomputes threat score every N seconds

Exposes:
  GET /              → serves static/index.html
  GET /api/status    → current threat status (score, level, why, actions, metrics)
  GET /api/events    → recent raw events from SQLite
  GET /api/timeline  → recent score snapshots for the timeline graph
  GET /api/sessions  → honeypot sessions (login + command events grouped by session)
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
import time
from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

import db
import collector
import scoring
import defense

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s – %(message)s",
)
logger = logging.getLogger("ghostwall")

app = FastAPI(title="GhostWall", version="0.1.0")

STATIC_DIR = Path(__file__).parent / "static"

# ---------------------------------------------------------------------------
# Lifecycle
# ---------------------------------------------------------------------------

@app.on_event("startup")
async def startup() -> None:
    await db.init_db()
    asyncio.create_task(collector.tail_log(), name="collector")
    asyncio.create_task(scoring.scoring_loop(), name="scoring")
    asyncio.create_task(_defense_loop(), name="defense")
    logger.info("GhostWall started.")


async def _defense_loop() -> None:
    """Run defense module every 10 seconds based on current threat state."""
    while True:
        try:
            state = scoring.get_state()
            actions = defense.apply_defense(state.level, state.top_ips)
            if actions:
                state.actions = actions
        except Exception as exc:
            logger.exception("Defense loop error: %s", exc)
        await asyncio.sleep(10)


# ---------------------------------------------------------------------------
# Static files / UI
# ---------------------------------------------------------------------------

app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")


@app.get("/", include_in_schema=False)
async def index() -> FileResponse:
    return FileResponse(STATIC_DIR / "index.html")


# ---------------------------------------------------------------------------
# API endpoints
# ---------------------------------------------------------------------------

@app.get("/api/status")
async def api_status() -> JSONResponse:
    state = scoring.get_state()
    metrics = dict(state.metrics)
    return JSONResponse({
        "score":   state.score,
        "level":   state.level,
        "why":     scoring._build_why(metrics),
        "actions": state.actions,
        "metrics": metrics,
        "top_ips":   [{"ip": ip, "count": c} for ip, c in state.top_ips],
        "top_users": [{"username": u, "count": c} for u, c in state.top_users],
    })


@app.get("/api/events")
async def api_events(limit: int = 200) -> JSONResponse:
    rows = await db.fetch_recent_events(limit)
    # Parse meta JSON strings
    for row in rows:
        if isinstance(row.get("meta"), str):
            try:
                row["meta"] = json.loads(row["meta"])
            except Exception:
                pass
    return JSONResponse(rows)


@app.get("/api/timeline")
async def api_timeline(limit: int = 300) -> JSONResponse:
    rows = await db.fetch_snapshots(limit)
    rows.reverse()  # chronological order
    return JSONResponse(rows)


@app.get("/api/sessions")
async def api_sessions() -> JSONResponse:
    """Return honeypot sessions grouped by session ID."""
    since = time.time() - 86400  # last 24 hours
    rows = await db.fetch_events_since(since)

    sessions: dict[str, dict] = {}
    for row in rows:
        try:
            meta = json.loads(row["meta"]) if isinstance(row["meta"], str) else row["meta"]
        except Exception:
            meta = {}

        sid = meta.get("session", "unknown")
        if sid not in sessions:
            sessions[sid] = {
                "session": sid,
                "src_ip":  row["src_ip"],
                "start":   row["ts"],
                "events":  [],
            }
        sessions[sid]["events"].append({
            "ts":   row["ts"],
            "kind": row["kind"],
            "meta": meta,
        })
        sessions[sid]["start"] = min(sessions[sid]["start"], row["ts"])

    result = sorted(sessions.values(), key=lambda s: s["start"], reverse=True)
    return JSONResponse(result[:50])
