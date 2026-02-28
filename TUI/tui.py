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
from collections import Counter, defaultdict, deque
from datetime import datetime
from pathlib import Path
from typing import Any

# Ensure project-root imports work when launched as `python3 TUI/tui.py`.
PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from Defense_Solutions.engine import build_defense_actions


SEVERITY_WEIGHT = {
    "connect.attempt": 1,
    "arp.scan": 4,
    "port.sweep": 6,
    "brute.force": 8,
}


class DashboardState:
    def __init__(self) -> None:
        self.started_at = time.time()
        self.total_events = 0
        self.event_counts: Counter[str] = Counter()
        self.ip_stats: dict[str, dict[str, Any]] = defaultdict(
            lambda: {"score": 0, "events": 0, "ports": set(), "last_seen": 0.0}
        )
        self.recent_events: deque[dict[str, Any]] = deque(maxlen=200)
        self.recent_actions: deque[dict[str, Any]] = deque(maxlen=100)

    def add_event(self, event: dict[str, Any]) -> None:
        event_type = str(event.get("type", "unknown"))
        src_ip = str(event.get("src_ip", "unknown"))
        port = event.get("port")
        ts = float(event.get("timestamp", time.time()))

        self.total_events += 1
        self.event_counts[event_type] += 1
        self.recent_events.appendleft(event)

        ip_state = self.ip_stats[src_ip]
        ip_state["events"] += 1
        ip_state["last_seen"] = ts
        ip_state["score"] += SEVERITY_WEIGHT.get(event_type, 1)
        if isinstance(port, int):
            ip_state["ports"].add(port)

        for action in build_defense_actions(event):
            self.recent_actions.appendleft(action)

    def uptime(self) -> str:
        seconds = int(time.time() - self.started_at)
        hours = seconds // 3600
        minutes = (seconds % 3600) // 60
        secs = seconds % 60
        return f"{hours:02}:{minutes:02}:{secs:02}"

    def top_attackers(self, count: int = 8) -> list[tuple[str, dict[str, Any]]]:
        ranked = sorted(
            self.ip_stats.items(),
            key=lambda item: (item[1]["score"], item[1]["events"]),
            reverse=True,
        )
        return ranked[:count]


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
    if height < 20 or width < 90:
        safe_addstr(stdscr, 1, 2, "Terminal too small. Resize to at least 90x20.", colors["warn"])
        safe_addstr(stdscr, 3, 2, "Press q to quit.", colors["dim"])
        stdscr.refresh()
        return

    title = " GHOSTWALL DEFENSE CONSOLE "
    safe_addstr(stdscr, 0, max(0, (width - len(title)) // 2), title, colors["banner"])
    safe_addstr(stdscr, 1, 2, f"Mode: {mode_label}", colors["base"])
    safe_addstr(stdscr, 1, width - 22, f"Uptime {state.uptime()}", colors["base"])

    card_y = 3
    card_h = 4
    card_w = width // 4 - 2
    spacing = 2
    left = 2

    draw_card(stdscr, card_y, left, card_h, card_w, "Events", colors)
    draw_card(stdscr, card_y, left + card_w + spacing, card_h, card_w, "Scans", colors)
    draw_card(stdscr, card_y, left + (card_w + spacing) * 2, card_h, card_w, "Brute", colors)
    draw_card(stdscr, card_y, left + (card_w + spacing) * 3, card_h, card_w, "Sources", colors)

    safe_addstr(stdscr, card_y + 2, left + 3, str(state.total_events), colors["chip_ok"])
    safe_addstr(stdscr, card_y + 2, left + card_w + spacing + 3, str(state.event_counts["port.sweep"] + state.event_counts["arp.scan"]), colors["chip_warn"])
    safe_addstr(stdscr, card_y + 2, left + (card_w + spacing) * 2 + 3, str(state.event_counts["brute.force"]), colors["chip_bad"])
    safe_addstr(stdscr, card_y + 2, left + (card_w + spacing) * 3 + 3, str(len(state.ip_stats)), colors["chip_ok"])

    body_y = card_y + card_h + 1
    body_h = height - body_y - 1
    left_w = width // 2 - 2
    right_w = width - left_w - 4

    draw_card(stdscr, body_y, 1, body_h // 2, left_w, "Top Sources", colors)
    draw_card(stdscr, body_y, left_w + 2, body_h // 2, right_w, "Recent Events", colors)
    draw_card(stdscr, body_y + body_h // 2, 1, body_h - body_h // 2, width - 2, "Defense Actions", colors)

    safe_addstr(stdscr, body_y + 1, 3, "IP", colors["title"])
    safe_addstr(stdscr, body_y + 1, 23, "Score", colors["title"])
    safe_addstr(stdscr, body_y + 1, 31, "Events", colors["title"])
    safe_addstr(stdscr, body_y + 1, 40, "Ports", colors["title"])
    for idx, (ip, details) in enumerate(state.top_attackers(count=max(1, body_h // 2 - 3))):
        row = body_y + 2 + idx
        ports = ",".join(map(str, sorted(details["ports"])[:6]))
        safe_addstr(stdscr, row, 3, ip, colors["base"])
        safe_addstr(stdscr, row, 23, str(details["score"]), colors["warn"] if details["score"] < 20 else colors["danger"])
        safe_addstr(stdscr, row, 31, str(details["events"]), colors["base"])
        safe_addstr(stdscr, row, 40, ports if ports else "-", colors["dim"])

    ev_x = left_w + 4
    for idx, event in enumerate(list(state.recent_events)[: max(1, body_h // 2 - 3)]):
        row = body_y + 2 + idx
        event_type = str(event.get("type", "unknown"))
        src_ip = str(event.get("src_ip", "unknown"))
        port = event.get("port", "-")
        when = datetime.fromtimestamp(float(event.get("timestamp", time.time()))).strftime("%H:%M:%S")
        sev_color = colors["base"]
        if event_type in ("port.sweep", "arp.scan"):
            sev_color = colors["warn"]
        if event_type == "brute.force":
            sev_color = colors["danger"]
        safe_addstr(stdscr, row, ev_x, f"{when}  {event_type:<14} {src_ip:<15} p:{port}", sev_color)

    act_y = body_y + body_h // 2 + 1
    for idx, action in enumerate(list(state.recent_actions)[: max(1, height - act_y - 2)]):
        row = act_y + 1 + idx
        severity = str(action.get("severity", "low"))
        color = colors["ok"] if severity == "low" else colors["warn"] if severity == "medium" else colors["danger"]
        summary = str(action.get("summary", ""))
        source = str(action.get("source", "-"))
        safe_addstr(stdscr, row, 3, f"[{severity.upper():6}] {source:<15} {summary}", color)

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
