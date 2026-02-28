"""
GhostWall TUI – full-screen terminal dashboard built with Textual.

Layout (3 columns × 2 rows):
┌─────────────────────────────────────────────────────────────┐
│  GhostWall                              ──── clock ────      │
├──────────────┬──────────────────────────┬───────────────────┤
│ THREAT       │ LIVE EVENT FEED          │ ATTACK INTEL      │
│ STATUS       │                          │                   │
│              │  HH:MM:SS SSH  failed…   │ Top IPs           │
│ Score: 42.0  │  HH:MM:SS FTP  connect   │ Top Usernames     │
│ [ORANGE]     │  …                       │ Banned            │
│              │                          │                   │
├──────────────┴──────────────────────────┴───────────────────┤
│ DEFENSE LOG / LLM DEBRIEF                                    │
└─────────────────────────────────────────────────────────────┘
"""
from __future__ import annotations

import asyncio
from datetime import datetime

from textual.app import App, ComposeResult
from textual.widgets import Header, Footer, Static, RichLog

LEVEL_STYLE = {
    "GREEN":  "bold green",
    "YELLOW": "bold yellow",
    "ORANGE": "bold dark_orange",
    "RED":    "bold red",
}
SERVICE_COLOR = {"ssh": "cyan", "ftp": "yellow", "telnet": "magenta"}
KIND_COLOR    = {"connect": "green", "failed_auth": "red",
                 "disconnect": "dim white", "ban": "bold red", "command": "blue"}


class GhostWallApp(App):
    CSS = """
    Screen {
        layout: grid;
        grid-size: 3 2;
        grid-rows: 5fr 1fr;
        grid-columns: 34 1fr 38;
    }

    #threat-panel {
        border: round $primary-darken-2;
        padding: 1 2;
        height: 100%;
    }

    #event-log {
        border: round $primary-darken-2;
        height: 100%;
    }

    #intel-panel {
        border: round $primary-darken-2;
        padding: 1 2;
        height: 100%;
    }

    #defense-log {
        column-span: 3;
        border: round $error-darken-2;
        height: 100%;
    }
    """

    TITLE     = "GhostWall"
    SUB_TITLE = "Autonomous Threat Detection"

    def __init__(self) -> None:
        super().__init__()
        from handler import Handler
        from scanner import Scanner
        self._queue: asyncio.Queue = asyncio.Queue()
        self._handler = Handler(self._queue)
        self._scanner = Scanner(self._queue)
        self._shown_events  = 0
        self._shown_defense = 0
        self._debrief_shown = False

    # ------------------------------------------------------------------
    # Layout
    # ------------------------------------------------------------------

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        yield Static("", id="threat-panel",  markup=True)
        yield RichLog(id="event-log",    highlight=True, markup=True, wrap=False)
        yield Static("", id="intel-panel",   markup=True)
        yield RichLog(id="defense-log",  highlight=True, markup=True)
        yield Footer()

    def on_mount(self) -> None:
        asyncio.create_task(self._scanner.start())
        asyncio.create_task(self._handler.run())
        self.set_interval(1.0, self._refresh)

    # ------------------------------------------------------------------
    # Periodic refresh
    # ------------------------------------------------------------------

    def _refresh(self) -> None:
        s = self._handler.state
        self._draw_threat(s)
        self._draw_intel(s)
        self._draw_events(s)
        self._draw_defense(s)

    def _draw_threat(self, s) -> None:
        level  = s.level
        score  = s.score
        style  = LEVEL_STYLE.get(level, "white")
        m      = s.metrics

        filled = int(score / 5)          # max 20 blocks
        bar    = (f"[{style}]{'█' * filled}[/]"
                  f"[dim]{'░' * (20 - filled)}[/]")

        text = (
            f"[bold]THREAT LEVEL[/]\n"
            f"[{style}]{'━' * 30}[/]\n\n"
            f"  Score  [{style}][bold]{score:>5.1f}[/][/] / 100\n"
            f"  {bar}\n\n"
            f"  Level  [{style}][bold]{level}[/][/]\n\n"
            f"[bold]METRICS[/]\n"
            f"[dim]{'━' * 30}[/]\n"
            f"  Fail/min    [red]{m.get('fail_rate', 0):>4}[/]\n"
            f"  Conn/min    [cyan]{m.get('conn_rate', 0):>4}[/]\n"
            f"  Unique IPs  [yellow]{m.get('unique_ips', 0):>4}[/]\n"
            f"  Offenders   [magenta]{m.get('repeat_offenders', 0):>4}[/]\n"
            f"  Bans        [bold red]{m.get('ban_events', 0):>4}[/]\n"
        )
        self.query_one("#threat-panel", Static).update(text)

    def _draw_intel(self, s) -> None:
        ip_lines = "\n".join(
            f"  [bold]{ip:<20}[/] [red]{cnt}[/]"
            for ip, cnt in s.top_ips[:7]
        ) or "  [dim]No data yet[/]"

        user_lines = "\n".join(
            f"  [bold]{u:<20}[/] [yellow]{cnt}[/]"
            for u, cnt in s.top_users[:5]
        ) or "  [dim]No data yet[/]"

        text = (
            f"[bold]TOP ATTACKERS[/]\n"
            f"[dim]{'━' * 35}[/]\n"
            f"{ip_lines}\n\n"
            f"[bold]TOP USERNAMES[/]\n"
            f"[dim]{'━' * 35}[/]\n"
            f"{user_lines}\n\n"
            f"[bold]BLOCKED[/]\n"
            f"[dim]{'━' * 35}[/]\n"
            f"  [bold red]{len(s.banned_ips)}[/] IP(s) banned\n"
        )
        self.query_one("#intel-panel", Static).update(text)

    def _draw_events(self, s) -> None:
        events = s.all_events
        if len(events) <= self._shown_events:
            return

        log = self.query_one("#event-log", RichLog)
        for ev in events[self._shown_events:]:
            ts      = datetime.fromtimestamp(ev.ts).strftime("%H:%M:%S")
            svc_c   = SERVICE_COLOR.get(ev.service, "white")
            kind_c  = KIND_COLOR.get(ev.kind, "white")
            meta    = ""
            if ev.meta.get("username"):
                meta = f" [dim]{ev.meta['username']}"
                if ev.meta.get("password"):
                    meta += f":{ev.meta['password']}"
                meta += "[/]"

            log.write(
                f"[dim]{ts}[/] [{svc_c}]{ev.service.upper():<7}[/] "
                f"[{kind_c}]{ev.kind:<12}[/] [bold]{ev.src_ip}[/]{meta}"
            )
        self._shown_events = len(events)

    def _draw_defense(self, s) -> None:
        log   = self.query_one("#defense-log", RichLog)
        items = s.defense_log

        if len(items) > self._shown_defense:
            for item in items[self._shown_defense:]:
                log.write(f"[bold red]>[/] {item}")
            self._shown_defense = len(items)

        if s.debrief and not self._debrief_shown:
            log.write(f"\n[bold cyan]LLM DEBRIEF:[/] {s.debrief}")
            self._debrief_shown = True
