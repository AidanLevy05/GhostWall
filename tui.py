#!/usr/bin/env python3
"""
GhostWall TUI — Terminal User Interface for the SSH Defense Monitor.

Requirements:
    pip install textual httpx

Usage:
    python tui.py
    python tui.py --url http://localhost:8000   # custom API URL

The TUI connects to the GhostWall FastAPI backend and displays:
  • Live threat score with progress bar and colour-coded level
  • Key metrics (fail rate, conn rate, unique IPs, bans)
  • Top offending IPs table
  • Top attempted usernames table
  • Scrolling real-time event log

Keyboard shortcuts:
  Q  — quit
  R  — force refresh
  C  — clear the event log
"""
from __future__ import annotations

import argparse
import asyncio
from datetime import datetime

import httpx
from rich.text import Text
from textual.app import App, ComposeResult
from textual.containers import Container, Horizontal, Vertical
from textual.reactive import reactive
from textual.widgets import DataTable, Footer, Header, RichLog, Static

# ── Constants ─────────────────────────────────────────────────────────────────

POLL_STATUS = 3   # seconds between /api/status polls
POLL_EVENTS = 5   # seconds between /api/events polls

LEVEL_COLOR: dict[str, str] = {
    "GREEN":  "green",
    "YELLOW": "yellow",
    "ORANGE": "dark_orange",
    "RED":    "red",
}

KIND_COLOR: dict[str, str] = {
    "failed_auth": "red",
    "login":       "green",
    "command":     "magenta",
    "connect":     "cyan",
    "disconnect":  "dim cyan",
    "ban":         "bold red",
    "download":    "yellow",
}


# ── Custom widgets ─────────────────────────────────────────────────────────────

class ThreatWidget(Static):
    """Displays the current threat score, progress bar, and threat level."""

    score: reactive[float] = reactive(0.0)
    level: reactive[str]   = reactive("GREEN")
    why:   reactive[str]   = reactive("")

    def render(self) -> Text:
        color  = LEVEL_COLOR.get(self.level, "white")
        width  = 22
        filled = round(self.score / 100 * width)
        bar    = "█" * filled + "░" * (width - filled)

        t = Text()
        t.append("\n  THREAT SCORE\n\n", style="bold white")
        t.append(f"  {self.score:5.1f} / 100\n\n", style=f"bold {color}")
        t.append(f"  [{bar}]\n\n", style=color)
        t.append(f"  ◆ {self.level}\n", style=f"bold {color}")
        if self.why:
            t.append(f"\n  {self.why}\n", style="dim white")
        return t


class MetricsWidget(Static):
    """Displays the five key threat metrics."""

    fail_rate:        reactive[float] = reactive(0.0)
    conn_rate:        reactive[float] = reactive(0.0)
    unique_ips:       reactive[int]   = reactive(0)
    repeat_offenders: reactive[int]   = reactive(0)
    ban_events:       reactive[int]   = reactive(0)

    def render(self) -> Text:
        t = Text()
        t.append("\n  METRICS\n\n", style="bold white")
        rows = [
            ("Fail Rate",       f"{self.fail_rate:.0f}",        "/min"),
            ("Conn Rate",       f"{self.conn_rate:.0f}",        "/min"),
            ("Unique IPs",      str(self.unique_ips),           "/10m"),
            ("Repeat Offend",   str(self.repeat_offenders),     ""),
            ("Ban Events",      str(self.ban_events),           "/10m"),
        ]
        for label, val, unit in rows:
            t.append(f"  {label:<16}", style="dim white")
            t.append(f"{val:>5}", style="bold cyan")
            t.append(f"  {unit}\n", style="dim")
        return t


class StatusBar(Static):
    """Bottom status line: connection state and last-update timestamp."""

    connected:   reactive[bool] = reactive(False)
    last_update: reactive[str]  = reactive("—")

    def render(self) -> Text:
        t = Text()
        if self.connected:
            t.append("● Connected", style="bold green")
        else:
            t.append("● Disconnected", style="bold red")
        t.append(f"   Last update: {self.last_update}", style="dim white")
        return t


# ── Main application ───────────────────────────────────────────────────────────

class GhostWallTUI(App):
    """GhostWall Terminal User Interface."""

    TITLE     = "GhostWall — SSH Defense Monitor"
    SUB_TITLE = "Real-time threat monitoring"

    BINDINGS = [
        ("q", "quit",      "Quit"),
        ("r", "refresh",   "Refresh"),
        ("c", "clear_log", "Clear log"),
    ]

    CSS = """
    Screen {
        background: #0d1117;
        color: #e6edf3;
    }

    Header {
        background: #161b22;
        color: #58a6ff;
        border-bottom: solid #30363d;
    }

    Footer {
        background: #161b22;
        color: #8b949e;
        border-top: solid #30363d;
    }

    /* ── Top row ── */
    #top-row {
        height: 13;
        margin-bottom: 1;
    }

    ThreatWidget {
        border: solid #30363d;
        width: 2fr;
        height: 100%;
    }

    MetricsWidget {
        border: solid #30363d;
        width: 3fr;
        height: 100%;
    }

    /* ── Tables row ── */
    #tables-row {
        height: 11;
        margin-bottom: 1;
    }

    #ip-table-box {
        border: solid #30363d;
        width: 1fr;
        height: 100%;
    }

    #user-table-box {
        border: solid #30363d;
        width: 1fr;
        height: 100%;
    }

    .section-title {
        background: #161b22;
        color: #58a6ff;
        padding: 0 1;
        height: 1;
    }

    DataTable {
        background: #0d1117;
        height: 1fr;
    }

    DataTable > .datatable--header {
        background: #161b22;
        color: #8b949e;
    }

    DataTable > .datatable--cursor {
        background: #1f6feb;
        color: white;
    }

    /* ── Event log ── */
    #log-box {
        border: solid #30363d;
        height: 1fr;
    }

    RichLog {
        background: #0d1117;
        height: 1fr;
        scrollbar-color: #30363d;
    }

    /* ── Status bar ── */
    StatusBar {
        height: 1;
        padding: 0 1;
        background: #161b22;
        border-top: solid #30363d;
    }
    """

    def __init__(self, api_url: str = "http://localhost:8000") -> None:
        super().__init__()
        self.api_url = api_url.rstrip("/")
        self._client: httpx.AsyncClient | None = None
        self._seen_event_ids: set[int] = set()

    # ── Lifecycle ─────────────────────────────────────────────────────────────

    async def on_mount(self) -> None:
        self._client = httpx.AsyncClient(base_url=self.api_url, timeout=5.0)

        # Add table columns once
        self.query_one("#ip-table",   DataTable).add_columns("IP Address", "Events (1h)")
        self.query_one("#user-table", DataTable).add_columns("Username",   "Attempts (1h)")

        # Start polling loops
        self.set_interval(POLL_STATUS, self._poll_status)
        self.set_interval(POLL_EVENTS, self._poll_events)

        # Immediate first fetch
        await self._poll_status()
        await self._poll_events()

    async def on_unmount(self) -> None:
        if self._client:
            await self._client.aclose()

    # ── Layout ────────────────────────────────────────────────────────────────

    def compose(self) -> ComposeResult:
        yield Header()
        with Vertical():
            # Threat score + metrics
            with Horizontal(id="top-row"):
                yield ThreatWidget(id="threat")
                yield MetricsWidget(id="metrics")

            # Top IPs + top usernames
            with Horizontal(id="tables-row"):
                with Container(id="ip-table-box"):
                    yield Static("Top Offending IPs", classes="section-title")
                    yield DataTable(id="ip-table", show_cursor=False)
                with Container(id="user-table-box"):
                    yield Static("Top Usernames Attempted", classes="section-title")
                    yield DataTable(id="user-table", show_cursor=False)

            # Scrolling event log
            with Container(id="log-box"):
                yield Static("Recent Events", classes="section-title")
                yield RichLog(id="event-log", highlight=True, markup=False, max_lines=500)

        yield StatusBar(id="status-bar")
        yield Footer()

    # ── Polling ───────────────────────────────────────────────────────────────

    async def _poll_status(self) -> None:
        status_bar = self.query_one("#status-bar", StatusBar)
        try:
            r = await self._client.get("/api/status")
            r.raise_for_status()
            data = r.json()
        except Exception:
            status_bar.connected = False
            return

        status_bar.connected   = True
        status_bar.last_update = datetime.now().strftime("%H:%M:%S")

        # Threat widget
        threat = self.query_one("#threat", ThreatWidget)
        threat.score = float(data.get("score", 0))
        threat.level = data.get("level", "GREEN")
        threat.why   = data.get("why", "")

        # Metrics widget — values are nested under "metrics"
        raw_metrics = data.get("metrics", {})
        m = self.query_one("#metrics", MetricsWidget)
        m.fail_rate        = float(raw_metrics.get("fail_rate", 0))
        m.conn_rate        = float(raw_metrics.get("conn_rate", 0))
        m.unique_ips       = int(raw_metrics.get("unique_ips", 0))
        m.repeat_offenders = int(raw_metrics.get("repeat_offenders", 0))
        m.ban_events       = int(raw_metrics.get("ban_events", 0))

        # Top IPs table — API returns {"ip": ..., "count": ...}
        ip_table = self.query_one("#ip-table", DataTable)
        ip_table.clear()
        for entry in data.get("top_ips", []):
            ip_table.add_row(
                entry.get("ip", "?"),
                str(entry.get("count", 0)),
            )

        # Top users table — API returns {"username": ..., "count": ...}
        user_table = self.query_one("#user-table", DataTable)
        user_table.clear()
        for entry in data.get("top_users", []):
            user_table.add_row(
                entry.get("username", "?"),
                str(entry.get("count", 0)),
            )

    async def _poll_events(self) -> None:
        try:
            r = await self._client.get("/api/events")
            r.raise_for_status()
            events: list[dict] = r.json()
        except Exception:
            return

        log = self.query_one("#event-log", RichLog)

        # Only show events we haven't rendered yet
        new_events = []
        for ev in events:
            ev_id = ev.get("id")
            if ev_id is None:
                # Fallback: use a tuple hash if no id field
                ev_id = hash((ev.get("ts"), ev.get("src_ip"), ev.get("kind")))
            if ev_id not in self._seen_event_ids:
                self._seen_event_ids.add(ev_id)
                new_events.append(ev)

        # Render oldest first so the log reads top-to-bottom chronologically
        new_events.sort(key=lambda e: e.get("ts", 0))
        for ev in new_events:
            self._render_event(log, ev)

    def _render_event(self, log: RichLog, ev: dict) -> None:
        ts     = ev.get("ts", 0)
        src_ip = ev.get("src_ip", "?")
        kind   = ev.get("kind", "?")
        meta   = ev.get("meta") or {}
        color  = KIND_COLOR.get(kind, "white")

        try:
            time_str = datetime.fromtimestamp(float(ts)).strftime("%H:%M:%S")
        except Exception:
            time_str = "??:??:??"

        # Collect interesting metadata fields
        meta_parts: list[str] = []
        for key in ("username", "password", "input", "url", "outfile"):
            val = meta.get(key)
            if val:
                # Truncate long values
                val_str = str(val)
                if len(val_str) > 40:
                    val_str = val_str[:37] + "..."
                meta_parts.append(f"{key}={val_str!r}")

        line = Text()
        line.append(f"[{time_str}] ", style="dim white")
        line.append(f"{kind:<14}", style=f"bold {color}")
        line.append(f"  {src_ip:<18}", style="cyan")
        if meta_parts:
            line.append("  " + "  ".join(meta_parts), style="dim white")
        log.write(line)

    # ── Actions ───────────────────────────────────────────────────────────────

    async def action_refresh(self) -> None:
        """Force an immediate data refresh."""
        await asyncio.gather(self._poll_status(), self._poll_events())

    def action_clear_log(self) -> None:
        """Clear the event log panel."""
        self.query_one("#event-log", RichLog).clear()


# ── Entry point ────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        description="GhostWall TUI — Terminal dashboard for the SSH Defense Monitor",
    )
    parser.add_argument(
        "--url",
        default="http://localhost:8000",
        metavar="URL",
        help="Base URL of the GhostWall API  (default: http://localhost:8000)",
    )
    args = parser.parse_args()

    GhostWallTUI(api_url=args.url).run()


if __name__ == "__main__":
    main()
