"""
GhostWall Terminal User Interface.

Built with Textual — a modern async TUI framework for Python.
Layout: three-column live dashboard with threat status, event feed,
and top-attackers / defense panel. Press D for LLM debrief, Q to quit.
"""
from __future__ import annotations

import asyncio
import json
import time
from datetime import datetime

from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Container, Horizontal, Vertical, ScrollableContainer
from textual.reactive import reactive
from textual.widget import Widget
from textual.widgets import Header, Footer, Static, Label, DataTable, RichLog

import db
import scoring
import scanner
from Defense_Solutions import defense_loop, get_active_bans
from LLM_Debrief import generate_debrief
from LLM_Debrief.debrief import get_last_debrief

# ---------------------------------------------------------------------------
# Colour mapping
# ---------------------------------------------------------------------------

LEVEL_COLOR = {
    "GREEN":  "green",
    "YELLOW": "yellow",
    "ORANGE": "dark_orange",
    "RED":    "red",
}

LEVEL_ICON = {
    "GREEN":  "●",
    "YELLOW": "▲",
    "ORANGE": "◆",
    "RED":    "■",
}

PROTO_COLOR = {
    "SSH":    "cyan",
    "FTP":    "magenta",
    "Telnet": "bright_blue",
    "SMTP":   "green",
}


# ---------------------------------------------------------------------------
# Widgets
# ---------------------------------------------------------------------------

class ThreatPanel(Static):
    """Left column: live threat score and metrics."""

    def render(self) -> str:
        state = scoring.get_state()
        score = state.score
        level = state.level
        color = LEVEL_COLOR.get(level, "white")
        icon  = LEVEL_ICON.get(level, "?")
        m     = state.metrics

        filled = int(score / 10)
        bar    = f"[{color}]{'█' * filled}[/][dim]{'░' * (10 - filled)}[/]"

        bans = get_active_bans()
        ban_lines = ""
        if bans:
            ban_lines = "\n[bold]Active Bans:[/]\n"
            for ip, exp in list(bans.items())[:5]:
                remaining = max(0, int(exp - time.time()))
                ban_lines += f"  [{color}]{ip}[/] [{remaining}s]\n"

        actions = state.actions
        action_lines = ""
        if actions:
            action_lines = "\n[bold]Defense Actions:[/]\n"
            for a in actions[-4:]:
                action_lines += f"  [dim]{a[:42]}[/]\n"

        return (
            f"[bold {color}]{icon} THREAT STATUS[/]\n"
            f"{'─' * 22}\n"
            f"Score : [{color}][bold]{score:.1f}[/][/] / 100\n"
            f"Level : [{color}][bold]{level}[/][/]\n\n"
            f"{bar}\n\n"
            f"[bold]Metrics (last 60s):[/]\n"
            f"  fail/min    {m.get('fail_rate', 0):>4}\n"
            f"  conn/min    {m.get('conn_rate', 0):>4}\n"
            f"  unique IPs  {m.get('unique_ips', 0):>4}\n"
            f"  repeat off  {m.get('repeat_offenders', 0):>4}\n"
            f"\n[bold]Total Events:[/] {state.total_events}"
            f"{ban_lines}{action_lines}"
        )


class AttackersPanel(Static):
    """Right column: top attacking IPs and usernames."""

    def render(self) -> str:
        state     = scoring.get_state()
        top_ips   = state.top_ips[:8]
        top_users = state.top_users[:6]

        lines = ["[bold]Top Attackers (1h):[/]\n" + "─" * 24]
        if top_ips:
            for i, (ip, count) in enumerate(top_ips, 1):
                bar = "█" * min(count, 10)
                lines.append(f" {i}. [cyan]{ip:<17}[/] [{count}]")
        else:
            lines.append("  [dim]No attackers yet[/]")

        lines += ["\n[bold]Top Usernames Tried:[/]\n" + "─" * 24]
        if top_users:
            for user, count in top_users:
                lines.append(f"  [yellow]{user:<18}[/] {count}x")
        else:
            lines.append("  [dim]No auth attempts yet[/]")

        return "\n".join(lines)


class DebriefPanel(Static):
    """Overlay / bottom panel showing LLM debrief text."""

    def render(self) -> str:
        text = get_last_debrief()
        return (
            "[bold cyan]═══ LLM Debrief ═══[/]\n"
            f"{text}\n\n"
            "[dim]Press D to refresh | Press E to close[/]"
        )


# ---------------------------------------------------------------------------
# Main App
# ---------------------------------------------------------------------------

class GhostWallApp(App):
    """GhostWall honeypot TUI."""

    CSS = """
    Screen {
        background: #0a0a0f;
    }

    Header {
        background: #1a1a2e;
        color: #00ff88;
        text-style: bold;
    }

    Footer {
        background: #1a1a2e;
        color: #888888;
    }

    #layout {
        layout: horizontal;
        height: 1fr;
    }

    #left {
        width: 26;
        border: solid #333366;
        padding: 0 1;
        background: #0d0d1a;
    }

    #middle {
        width: 1fr;
        border: solid #333366;
        background: #0a0a12;
    }

    #right {
        width: 26;
        border: solid #333366;
        padding: 0 1;
        background: #0d0d1a;
    }

    ThreatPanel {
        height: 1fr;
        color: #cccccc;
    }

    AttackersPanel {
        height: 1fr;
        color: #cccccc;
    }

    #event-log {
        height: 1fr;
    }

    #debrief-container {
        height: 14;
        border: double cyan;
        background: #050510;
        padding: 0 1;
        display: none;
    }

    #debrief-container.visible {
        display: block;
    }
    """

    BINDINGS = [
        Binding("q", "quit",    "Quit"),
        Binding("d", "debrief", "LLM Debrief"),
        Binding("e", "hide_debrief", "Close Debrief"),
    ]

    _debrief_visible: reactive[bool] = reactive(False)

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        with Vertical():
            with Horizontal(id="layout"):
                with Container(id="left"):
                    yield ThreatPanel(id="threat")
                with Container(id="middle"):
                    yield RichLog(id="event-log", highlight=True, markup=True)
                with Container(id="right"):
                    yield AttackersPanel(id="attackers")
            with Container(id="debrief-container"):
                yield DebriefPanel(id="debrief")
        yield Footer()

    async def on_mount(self) -> None:
        # Initialise DB and start background tasks inside textual's event loop
        await db.init_db()
        asyncio.create_task(scanner.start_listeners(), name="scanner")
        asyncio.create_task(scoring.scoring_loop(),    name="scoring")
        asyncio.create_task(defense_loop(),             name="defense")

        # Seed the event log header
        log = self.query_one("#event-log", RichLog)
        log.write(
            "[bold cyan]GhostWall Event Feed[/]  "
            "[dim]listening on ports 22 (SSH)  21 (FTP)  23 (Telnet)[/]"
        )
        log.write("[dim]" + "─" * 60 + "[/]")

        # Kick off periodic refresh
        self.set_interval(2.0, self._refresh_panels)
        self.set_interval(2.0, self._poll_new_events)

        # Track last seen event id
        self._last_event_id: int = 0

    # ------------------------------------------------------------------
    # Periodic updates
    # ------------------------------------------------------------------

    async def _refresh_panels(self) -> None:
        self.query_one("#threat",    ThreatPanel).refresh()
        self.query_one("#attackers", AttackersPanel).refresh()
        if self._debrief_visible:
            self.query_one("#debrief", DebriefPanel).refresh()

        # Update header subtitle with current score
        state = scoring.get_state()
        color = LEVEL_COLOR.get(state.level, "white")
        self.title = (
            f"GhostWall  |  Score: {state.score:.1f}  |  Level: {state.level}"
        )

    async def _poll_new_events(self) -> None:
        """Fetch recent events and write new ones to the log."""
        log    = self.query_one("#event-log", RichLog)
        events = await db.fetch_recent_events(limit=60)

        # events come newest-first; reverse for chronological display
        new_events = [
            e for e in reversed(events)
            if e["id"] > self._last_event_id
        ]

        for e in new_events:
            self._last_event_id = max(self._last_event_id, e["id"])
            ts    = datetime.fromtimestamp(e["ts"]).strftime("%H:%M:%S")
            proto = e.get("proto", "?")
            kind  = e["kind"]
            ip    = e["src_ip"]
            c     = PROTO_COLOR.get(proto, "white")

            try:
                meta = json.loads(e["meta"]) if isinstance(e["meta"], str) else e["meta"]
            except Exception:
                meta = {}

            detail = ""
            if kind == "failed_auth":
                user = meta.get("username", "")
                pw   = meta.get("password", "")
                if user:
                    detail = f" [dim]user=[yellow]{user}[/][/]"
                if pw:
                    detail += f" [dim]pass=[red]{pw}[/][/]"

            kind_color = {
                "connect":     "bright_green",
                "failed_auth": "red",
                "disconnect":  "dim",
                "command":     "yellow",
                "download":    "magenta",
            }.get(kind, "white")

            log.write(
                f"[dim]{ts}[/]  [{c}]{proto:<7}[/]  "
                f"[{kind_color}]{kind:<12}[/]  "
                f"[cyan]{ip}[/]{detail}"
            )

    # ------------------------------------------------------------------
    # Key actions
    # ------------------------------------------------------------------

    async def action_debrief(self) -> None:
        self._debrief_visible = True
        container = self.query_one("#debrief-container")
        container.add_class("visible")
        # Generate in background without blocking TUI
        asyncio.create_task(generate_debrief())

    async def action_hide_debrief(self) -> None:
        self._debrief_visible = False
        self.query_one("#debrief-container").remove_class("visible")

    async def action_quit(self) -> None:
        self.exit()
