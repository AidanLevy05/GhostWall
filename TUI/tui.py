#!/usr/bin/env python3
"""GhostWall terminal dashboard.

Run modes:
- Demo mode: python3 TUI/tui.py --demo
- Read scanner output from stdin:
    sudo .venv/bin/python scanner.py eth0 | python3 TUI/tui.py --stdin
- Follow a JSONL event file:
    python3 TUI/tui.py --follow /path/to/events.jsonl
"""

from __future__ import annotations

import argparse
import ast
import curses
import json
import queue
import random
import sys
import threading
import time
import textwrap
from collections import Counter, defaultdict, deque
from datetime import datetime
from pathlib import Path
from typing import Any

# Ensure project-root imports work when launched as `python3 TUI/tui.py`.
PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from Defense_Solutions.engine import build_defense_actions


BASE_EVENT_SCORE = {
    "connect.attempt": 12,
    "arp.scan": 28,
    "port.sweep": 45,
    "brute.force": 75,
}


class DashboardState:
    def __init__(self) -> None:
        self.started_at = time.time()
        self.total_events = 0
        self.event_counts: Counter[str] = Counter()
        self.recent_events: deque[dict[str, Any]] = deque(maxlen=400)
        self.recent_logs: deque[dict[str, Any]] = deque(maxlen=250)
        self.recent_scores: deque[int] = deque(maxlen=300)
        self.ip_last_seen: dict[str, float] = defaultdict(float)
        self.recent_actions: deque[dict[str, Any]] = deque(maxlen=120)

    def _score_event(self, event: dict[str, Any]) -> int:
        event_type = str(event.get("type", "unknown"))
        base = BASE_EVENT_SCORE.get(event_type, 10)

        count = event.get("count", 0)
        if isinstance(count, int):
            base += min(20, max(0, count // 2))

        ports = event.get("ports", [])
        if isinstance(ports, list):
            base += min(15, len(ports) * 2)

        port = event.get("port")
        if port == 22:
            base += 5

        return max(0, min(99, base))

    def _response_for_score(self, score: int) -> tuple[str, str]:
        if 0 <= score <= 19:
            return ("Alert only", "ok")
        if 20 <= score <= 49:
            return ("Open honeypot 15m", "warn")
        return ("Open honeypot 1h", "danger")

    def add_event(self, event: dict[str, Any]) -> None:
        event_type = str(event.get("type", "unknown"))
        src_ip = str(event.get("src_ip", "unknown"))
        ts = float(event.get("timestamp", time.time()))
        port = event.get("port", "-")
        score = self._score_event(event)
        response_text, response_color = self._response_for_score(score)

        self.total_events += 1
        self.event_counts[event_type] += 1
        self.recent_events.appendleft(event)
        self.recent_scores.appendleft(score)
        self.ip_last_seen[src_ip] = ts

        self.recent_logs.appendleft(
            {
                "timestamp": ts,
                "src_ip": src_ip,
                "type": event_type,
                "port": port,
                "score": score,
                "response": response_text,
                "response_color": response_color,
            }
        )

        for action in build_defense_actions(event):
            self.recent_actions.appendleft(action)

    def uptime(self) -> str:
        seconds = int(time.time() - self.started_at)
        hours = seconds // 3600
        minutes = (seconds % 3600) // 60
        secs = seconds % 60
        return f"{hours:02}:{minutes:02}:{secs:02}"

    def average_weighted_threat(self) -> float:
        if not self.recent_scores:
            return 0.0
        return sum(self.recent_scores) / len(self.recent_scores)

    def current_attack_count(self, window_seconds: int = 30) -> int:
        cutoff = time.time() - window_seconds
        return sum(1 for ev in self.recent_events if float(ev.get("timestamp", 0.0)) >= cutoff)

    def active_source_count(self, window_seconds: int = 60) -> int:
        cutoff = time.time() - window_seconds
        return sum(1 for _, ts in self.ip_last_seen.items() if ts >= cutoff)


def parse_event_line(line: str) -> dict[str, Any] | None:
    text = line.strip()
    if not text:
        return None

    for parser in (json.loads, ast.literal_eval):
        try:
            event = parser(text)
            if isinstance(event, dict):
                return event
        except Exception:
            continue
    return None


def start_demo_source(out_q: queue.Queue[dict[str, Any]]) -> threading.Thread:
    attackers = ["192.168.1.10", "10.0.0.22", "172.16.5.17", "185.220.101.3"]
    targets = [22, 21, 80, 443, 8080, 3306, 5432]
    event_types = ["connect.attempt", "connect.attempt", "arp.scan", "port.sweep", "brute.force"]

    def run() -> None:
        while True:
            now = time.time()
            event_type = random.choice(event_types)
            port = random.choice(targets)
            event: dict[str, Any] = {
                "type": event_type,
                "src_ip": random.choice(attackers),
                "timestamp": now,
                "port": port,
            }
            if event_type == "port.sweep":
                event["ports"] = random.sample(targets, k=random.randint(3, min(7, len(targets))))
                event["count"] = len(event["ports"])
            if event_type == "arp.scan":
                event["target"] = "192.168.1.1"
            if event_type == "brute.force":
                event["count"] = random.randint(10, 30)

            out_q.put(event)
            time.sleep(random.uniform(0.2, 0.8))

    thread = threading.Thread(target=run, daemon=True)
    thread.start()
    return thread


def start_stdin_source(out_q: queue.Queue[dict[str, Any]]) -> threading.Thread:
    import sys

    def run() -> None:
        for line in sys.stdin:
            event = parse_event_line(line)
            if event is not None:
                out_q.put(event)

    thread = threading.Thread(target=run, daemon=True)
    thread.start()
    return thread


def start_follow_source(path: Path, out_q: queue.Queue[dict[str, Any]]) -> threading.Thread:
    def run() -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.touch(exist_ok=True)
        with path.open("r", encoding="utf-8") as file:
            file.seek(0, 2)
            while True:
                line = file.readline()
                if not line:
                    time.sleep(0.2)
                    continue
                event = parse_event_line(line)
                if event is not None:
                    out_q.put(event)

    thread = threading.Thread(target=run, daemon=True)
    thread.start()
    return thread


def safe_addstr(win: curses.window, y: int, x: int, text: str, attr: int = 0) -> None:
    h, w = win.getmaxyx()
    if y < 0 or y >= h or x >= w:
        return
    available = max(0, w - x - 1)
    if available <= 0:
        return
    win.addstr(y, x, text[:available], attr)


def add_wrapped_text(
    win: curses.window,
    y: int,
    x: int,
    text: str,
    width: int,
    attr: int = 0,
    max_lines: int | None = None,
) -> int:
    if width <= 0:
        return 0
    lines = textwrap.wrap(text, width=width, break_long_words=True, break_on_hyphens=True) or [""]
    if max_lines is not None:
        lines = lines[:max_lines]
    for idx, line in enumerate(lines):
        safe_addstr(win, y + idx, x, line, attr)
    return len(lines)


def init_colors() -> dict[str, int]:
    curses.start_color()
    curses.use_default_colors()
    curses.init_pair(1, curses.COLOR_BLACK, curses.COLOR_CYAN)
    curses.init_pair(2, curses.COLOR_BLACK, curses.COLOR_GREEN)
    curses.init_pair(3, curses.COLOR_BLACK, curses.COLOR_YELLOW)
    curses.init_pair(4, curses.COLOR_BLACK, curses.COLOR_RED)
    curses.init_pair(5, curses.COLOR_CYAN, -1)
    curses.init_pair(6, curses.COLOR_GREEN, -1)
    curses.init_pair(7, curses.COLOR_YELLOW, -1)
    curses.init_pair(8, curses.COLOR_RED, -1)
    curses.init_pair(9, curses.COLOR_WHITE, -1)

    return {
        "banner": curses.color_pair(1) | curses.A_BOLD,
        "ok": curses.color_pair(6) | curses.A_BOLD,
        "warn": curses.color_pair(7) | curses.A_BOLD,
        "danger": curses.color_pair(8) | curses.A_BOLD,
        "title": curses.color_pair(5) | curses.A_BOLD,
        "dim": curses.A_DIM,
        "base": curses.color_pair(9),
        "chip_ok": curses.color_pair(2) | curses.A_BOLD,
        "chip_warn": curses.color_pair(3) | curses.A_BOLD,
        "chip_bad": curses.color_pair(4) | curses.A_BOLD,
    }


def draw_card(stdscr: curses.window, y: int, x: int, h: int, w: int, title: str, colors: dict[str, int]) -> None:
    if h < 3 or w < 4:
        return
    for ix in range(x, x + w):
        if y < stdscr.getmaxyx()[0]:
            stdscr.addch(y, ix, ord(" "))
    safe_addstr(stdscr, y, x + 2, f" {title} ", colors["title"])
    for iy in range(y, y + h):
        if iy < stdscr.getmaxyx()[0]:
            if x < stdscr.getmaxyx()[1]:
                stdscr.addch(iy, x, ord("|"), colors["dim"])
            if x + w - 1 < stdscr.getmaxyx()[1]:
                stdscr.addch(iy, x + w - 1, ord("|"), colors["dim"])
    for ix in range(x, x + w):
        if y + h - 1 < stdscr.getmaxyx()[0]:
            stdscr.addch(y + h - 1, ix, ord("-"), colors["dim"])
    if y + h - 1 < stdscr.getmaxyx()[0] and x < stdscr.getmaxyx()[1]:
        stdscr.addch(y + h - 1, x, ord("+"), colors["dim"])
    if y + h - 1 < stdscr.getmaxyx()[0] and x + w - 1 < stdscr.getmaxyx()[1]:
        stdscr.addch(y + h - 1, x + w - 1, ord("+"), colors["dim"])


def render(stdscr: curses.window, state: DashboardState, mode_label: str, colors: dict[str, int]) -> None:
    stdscr.erase()
    height, width = stdscr.getmaxyx()
    if height < 22 or width < 90:
        safe_addstr(stdscr, 1, 2, "Terminal too small. Resize to at least 90x22.", colors["warn"])
        safe_addstr(stdscr, 3, 2, "Press q to quit.", colors["dim"])
        stdscr.refresh()
        return

    top_h = 7
    mid_h = max(8, (height - top_h - 2) // 2)
    bot_h = height - top_h - mid_h - 1

    draw_card(stdscr, 0, 1, top_h, width - 2, "Attack Summary", colors)
    draw_card(stdscr, top_h, 1, mid_h, width - 2, "Current Logs + Threat Level", colors)
    draw_card(stdscr, top_h + mid_h, 1, bot_h, width - 2, "Response Decisions", colors)

    avg_threat = state.average_weighted_threat()
    avg_color = colors["ok"] if avg_threat < 20 else colors["warn"] if avg_threat < 50 else colors["danger"]
    safe_addstr(stdscr, 1, 3, "GHOSTWALL THREAT CONTROL", colors["banner"])
    safe_addstr(stdscr, 2, 3, f"Mode: {mode_label}   Uptime: {state.uptime()}", colors["base"])
    safe_addstr(stdscr, 3, 3, f"Current attacks (30s): {state.current_attack_count()}", colors["chip_warn"])
    safe_addstr(stdscr, 3, 34, f"Active sources (60s): {state.active_source_count()}", colors["chip_ok"])
    safe_addstr(stdscr, 3, 66, f"Total events: {state.total_events}", colors["base"])
    safe_addstr(stdscr, 4, 3, f"Average weighted threat: {avg_threat:05.2f}/99", avg_color)
    add_wrapped_text(
        stdscr,
        4,
        45,
        "Policy: 0-19 ALERT, 20-49 HONEYPOT(15m), 50-99 HONEYPOT(1h)",
        width=max(12, width - 48),
        attr=colors["title"],
        max_lines=2,
    )

    safe_addstr(stdscr, top_h + 1, 3, "TIME", colors["title"])
    safe_addstr(stdscr, top_h + 1, 12, "SRC IP", colors["title"])
    safe_addstr(stdscr, top_h + 1, 29, "EVENT", colors["title"])
    safe_addstr(stdscr, top_h + 1, 44, "PORT", colors["title"])
    safe_addstr(stdscr, top_h + 1, 52, "THREAT", colors["title"])
    safe_addstr(stdscr, top_h + 1, 62, "AUTO RESPONSE", colors["title"])

    mid_rows = max(1, mid_h - 3)
    for idx, log in enumerate(list(state.recent_logs)[:mid_rows]):
        row = top_h + 2 + idx
        when = datetime.fromtimestamp(float(log["timestamp"])).strftime("%H:%M:%S")
        score = int(log["score"])
        response = str(log["response"])
        event_color = colors["ok"] if score < 20 else colors["warn"] if score < 50 else colors["danger"]
        safe_addstr(stdscr, row, 3, when, colors["base"])
        safe_addstr(stdscr, row, 12, str(log["src_ip"]), colors["base"])
        safe_addstr(stdscr, row, 29, f"{str(log['type']):<15}", event_color)
        safe_addstr(stdscr, row, 46, str(log["port"]), colors["base"])
        safe_addstr(stdscr, row, 52, f"{score:02d}/99", event_color)
        safe_addstr(stdscr, row, 62, response, event_color)

    base_y = top_h + mid_h
    safe_addstr(stdscr, base_y + 1, 3, "DECISION BANDS:", colors["title"])
    safe_addstr(stdscr, base_y + 2, 3, "0-19  -> Send alert only", colors["ok"])
    safe_addstr(stdscr, base_y + 3, 3, "20-49 -> Open honeypot for 15 minutes (theoretical)", colors["warn"])
    safe_addstr(stdscr, base_y + 4, 3, "50-99 -> Open honeypot for 1 hour (theoretical)", colors["danger"])
    safe_addstr(stdscr, base_y + 1, 54, "LATEST DEFENSE ACTIONS", colors["title"])

    action_rows = max(1, bot_h - 3)
    row = base_y + 2
    for action in list(state.recent_actions):
        if row >= base_y + 2 + action_rows:
            break
        severity = str(action.get("severity", "low")).lower()
        color = colors["ok"] if severity == "low" else colors["warn"] if severity in {"medium", "high"} else colors["danger"]
        src = str(action.get("src_ip", "-"))
        source = str(action.get("source", "-"))
        summary = str(action.get("summary", ""))
        prefix = f"[{severity.upper():8}] {src:<15} {source:<10} "
        summary_width = max(12, width - 56 - len(prefix))
        wrapped = textwrap.wrap(summary, width=summary_width, break_long_words=True, break_on_hyphens=True) or [""]
        safe_addstr(stdscr, row, 54, prefix + wrapped[0], color)
        row += 1
        indent = " " * len(prefix)
        for continuation in wrapped[1:]:
            if row >= base_y + 2 + action_rows:
                break
            safe_addstr(stdscr, row, 54, indent + continuation, color)
            row += 1

    safe_addstr(stdscr, height - 1, 2, "q quit  c clear  arrows/home/end no-op", colors["dim"])
    stdscr.refresh()


def run_dashboard(stdscr: curses.window, event_q: queue.Queue[dict[str, Any]], mode_label: str) -> None:
    curses.curs_set(0)
    stdscr.nodelay(True)
    stdscr.timeout(100)
    colors = init_colors()
    state = DashboardState()

    while True:
        while True:
            try:
                state.add_event(event_q.get_nowait())
            except queue.Empty:
                break

        render(stdscr, state, mode_label, colors)
        key = stdscr.getch()
        if key in (ord("q"), ord("Q")):
            return
        if key in (ord("c"), ord("C")):
            state = DashboardState()


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="GhostWall TUI dashboard")
    parser.add_argument("--demo", action="store_true", help="Generate synthetic attack events")
    parser.add_argument("--stdin", action="store_true", help="Read event objects from stdin")
    parser.add_argument("--follow", type=Path, help="Tail a JSONL-like event file")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    event_q: queue.Queue[dict[str, Any]] = queue.Queue()

    selected = [args.demo, args.stdin, bool(args.follow)]
    if sum(bool(x) for x in selected) > 1:
        raise SystemExit("Pick one mode: --demo OR --stdin OR --follow <path>")

    mode_label = "demo"
    if args.demo:
        start_demo_source(event_q)
        mode_label = "demo"
    elif args.stdin:
        start_stdin_source(event_q)
        mode_label = "stdin"
    elif args.follow:
        start_follow_source(args.follow, event_q)
        mode_label = f"follow:{args.follow}"
    else:
        start_demo_source(event_q)
        mode_label = "demo (default)"

    curses.wrapper(run_dashboard, event_q, mode_label)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
