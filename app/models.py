"""
Pydantic models for SSH-Shield events and snapshots.
"""
from __future__ import annotations

from typing import Any, Dict, Optional
from pydantic import BaseModel


class Event(BaseModel):
    """A normalized event ingested from the Cowrie JSON log."""
    ts: float                          # Unix timestamp
    src_ip: str                        # Attacker source IP
    kind: str                          # Event kind: failed_auth, login, command, connect, disconnect, ban
    meta: Dict[str, Any] = {}         # Extra fields (username, password, command, session, etc.)


class Snapshot(BaseModel):
    """A periodic metrics snapshot stored in SQLite."""
    ts: float                          # Unix timestamp of snapshot
    score: float                       # Threat score 0–100
    level: str                         # GREEN / YELLOW / ORANGE / RED
    fail_rate: float                   # Failed-auth events per minute (last 60 s)
    conn_rate: float                   # Connection events per minute (last 60 s)
    unique_ips: int                    # Unique source IPs in last 10 minutes
    repeat_offenders: int              # IPs with >3 events in last hour
    ban_events: int                    # Ban events in last 10 minutes


class ThreatStatus(BaseModel):
    """Live threat status returned by /api/status."""
    score: float
    level: str
    why: str                           # Human-readable reason line
    actions: list[str]                 # Actions taken / recorded this cycle
    metrics: Dict[str, Any]
