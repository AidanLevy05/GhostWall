#!/usr/bin/env python3
"""GhostWall terminal dashboard.

Run modes:
- Live mode (default): sudo venv/bin/python3 TUI/tui.py --interface wlp0s20f3
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
import os
import queue
import random
import socket
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
from Defense_Solutions.fport import fssh
from LLM_Debrief.chatbot import LocalDebrief


BASE_EVENT_SCORE = {
    "connect.attempt": 12,
    "arp.scan": 28,
    "port.sweep": 45,
    "brute.force": 75,
    "fssh.route": 18,
    "fssh.config": 5,
    "fssh.status": 5,
    "fssh.warn": 35,
    "fssh.error": 65,
    "cowrie.login.failed": 55,
    "cowrie.command.input": 70,
    "cowrie.session.file_download": 85,
    "cowrie.session.connect": 48,
}


class DashboardState:
    def __init__(self, log_file: Path | None = None) -> None:
        self.started_at = time.time()
        self.total_events = 0
        self.event_counts: Counter[str] = Counter()
        self.recent_events: deque[dict[str, Any]] = deque(maxlen=400)
        self.recent_logs: deque[dict[str, Any]] = deque(maxlen=250)
        self.recent_scores: deque[int] = deque(maxlen=300)
        self.ip_last_seen: dict[str, float] = defaultdict(float)
        self.recent_actions: deque[dict[str, Any]] = deque(maxlen=120)
        self.port_counts: Counter[int] = Counter()
        self.cowrie_events = 0
        self.next_log_id = 1
        self.log_file = log_file
        self.debrief: dict[str, Any] = {
            "backend": "heuristic",
            "level": "low",
            "summary": "Waiting for a completed attack session...",
            "actions": ["No recommendations yet."],
        }
        self.current_attack_events: deque[dict[str, Any]] = deque(maxlen=5000)
        self.current_attack_started_at: float | None = None
        self.current_attack_last_event_at: float | None = None
        self.last_completed_attack: dict[str, Any] | None = None
        self.last_report_generated_at: float | None = None
        self.service_by_port = {
            21: "FTP decoy",
            22: "SSH real",
            2222: "Cowrie honeypot",
            80: "HTTP",
            443: "HTTPS",
            8080: "HTTP-alt",
        }

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
                "id": self.next_log_id,
                "timestamp": ts,
                "src_ip": src_ip,
                "type": event_type,
                "port": port,
                "score": score,
                "response": response_text,
                "response_color": response_color,
            }
        )
        self.next_log_id += 1
        if isinstance(port, int):
            self.port_counts[port] += 1
        if event_type.startswith("cowrie."):
            self.cowrie_events += 1

        if self.log_file is not None:
            self._write_log_line(
                f"{int(ts)} id={self.next_log_id - 1} src={src_ip} event={event_type} port={port} score={score} response={response_text}"
            )

        if self.current_attack_started_at is None:
            self.current_attack_started_at = ts
        self.current_attack_last_event_at = ts
        self.current_attack_events.append(event)

        for action in build_defense_actions(event):
            self.recent_actions.appendleft(action)

    def _write_log_line(self, line: str) -> None:
        try:
            self.log_file.parent.mkdir(parents=True, exist_ok=True)
            with self.log_file.open("a", encoding="utf-8") as f:
                f.write(line + "\n")
        except Exception:
            pass

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

    def snapshot(self) -> dict[str, Any]:
        return {
            "avg_threat": self.average_weighted_threat(),
            "current_attacks": self.current_attack_count(),
            "active_sources": self.active_source_count(),
            "cowrie_events": self.cowrie_events,
            "top_event_type": self.event_counts.most_common(1)[0][0] if self.event_counts else "none",
        }

    def maybe_close_attack_session(self, idle_gap_seconds: float = 8.0, min_events: int = 4) -> dict[str, Any] | None:
        if self.current_attack_last_event_at is None or self.current_attack_started_at is None:
            return None
        if len(self.current_attack_events) < min_events:
            return None
        if time.time() - self.current_attack_last_event_at < idle_gap_seconds:
            return None

        events = list(self.current_attack_events)
        type_counts: Counter[str] = Counter(str(e.get("type", "unknown")) for e in events)
        source_counts: Counter[str] = Counter(str(e.get("src_ip", "unknown")) for e in events)
        ports = sorted({int(e["port"]) for e in events if isinstance(e.get("port"), int)})
        scores = [self._score_event(e) for e in events]

        session = {
            "attack_started_at": self.current_attack_started_at,
            "attack_ended_at": self.current_attack_last_event_at,
            "duration_seconds": round(self.current_attack_last_event_at - self.current_attack_started_at, 2),
            "event_count": len(events),
            "avg_threat": (sum(scores) / len(scores)) if scores else 0.0,
            "max_threat": max(scores) if scores else 0,
            "cowrie_events": sum(1 for e in events if str(e.get("type", "")).startswith("cowrie.")),
            "top_event_type": type_counts.most_common(1)[0][0] if type_counts else "none",
            "top_source": source_counts.most_common(1)[0][0] if source_counts else "none",
            "unique_sources": len(source_counts),
            "ports_touched": ports[:30],
            "event_type_breakdown": dict(type_counts),
        }

        self.last_completed_attack = session
        self.current_attack_events.clear()
        self.current_attack_started_at = None
        self.current_attack_last_event_at = None
        return session

    def top_ports(self, count: int = 12) -> list[tuple[int, int, str]]:
        ranked = self.port_counts.most_common(count)
        return [(p, c, self.service_by_port.get(p, "unknown")) for p, c in ranked]


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


def parse_cowrie_line(line: str) -> dict[str, Any] | None:
    try:
        data = json.loads(line.strip())
    except Exception:
        return None
    if not isinstance(data, dict):
        return None

    event_id = str(data.get("eventid", "cowrie.unknown"))
    src_ip = str(data.get("src_ip", "unknown"))
    ts = float(data.get("timestamp", time.time())) if isinstance(data.get("timestamp"), (int, float)) else time.time()
    dst_port = data.get("dst_port", 22)
    if not isinstance(dst_port, int):
        dst_port = 22

    mapped = {
        "cowrie.login.failed": "cowrie.login.failed",
        "cowrie.command.input": "cowrie.command.input",
        "cowrie.session.file_download": "cowrie.session.file_download",
        "cowrie.session.connect": "cowrie.session.connect",
    }
    event_type = mapped.get(event_id, "cowrie.session.connect")
    out = {"type": event_type, "src_ip": src_ip, "timestamp": ts, "port": dst_port}
    if "input" in data:
        out["command"] = str(data.get("input", ""))[:80]
    return out


def parse_action_line(line: str) -> dict[str, Any] | None:
    try:
        data = json.loads(line.strip())
    except Exception:
        return None
    if not isinstance(data, dict):
        return None
    if "source" not in data or "severity" not in data:
        return None
    return data


def parse_whitelist(value: str) -> list[str]:
    ips: list[str] = []
    for raw in value.split(","):
        ip = raw.strip()
        if ip:
            ips.append(ip)
    return ips


def start_live_source(args: argparse.Namespace, out_q: queue.Queue[dict[str, Any]]) -> socket.socket:
    import scanner

    if os.geteuid() != 0:
        raise SystemExit("Live mode requires sudo/root (packet sniffing + low port bind).")

    whitelist_ips = parse_whitelist(args.whitelist)
    force_honeypot_ips = parse_whitelist(args.force_honeypot)
    fssh.set_log_callback(out_q.put)
    fssh.LISTEN_PORT = int(args.listen_port)
    fssh.set_port_map(real_port=int(args.real_ssh_port), honeypot_port=int(args.cowrie_port))
    fssh.set_whitelist(whitelist_ips)
    fssh.set_force_honeypot(force_honeypot_ips)
    try:
        server = fssh.start()
    except OSError as exc:
        if exc.errno == 98:
            raise SystemExit(
                f"Cannot bind fssh to :{args.listen_port}; port is already in use. "
                f"Run: sudo ss -ltnp 'sport = :{args.listen_port}'"
            ) from exc
        raise

    scanner.start(args.interface, out_q)
    return server


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


def start_cowrie_source(path: Path, out_q: queue.Queue[dict[str, Any]]) -> threading.Thread:
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
                event = parse_cowrie_line(line)
                if event is not None:
                    out_q.put(event)

    thread = threading.Thread(target=run, daemon=True)
    thread.start()
    return thread


def start_actions_source(path: Path, out_q: queue.Queue[dict[str, Any]]) -> threading.Thread:
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
                action = parse_action_line(line)
                if action is not None:
                    out_q.put(action)

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


def render(stdscr: curses.window, state: DashboardState, mode_label: str, colors: dict[str, int], log_scroll: int) -> None:
    stdscr.erase()
    height, width = stdscr.getmaxyx()
    if height < 24 or width < 100:
        safe_addstr(stdscr, 1, 2, "Terminal too small. Resize to at least 100x24.", colors["warn"])
        safe_addstr(stdscr, 3, 2, "Press q to quit.", colors["dim"])
        stdscr.refresh()
        return

    left_w = 34
    right_x = left_w + 1
    right_w = width - right_x - 1

    left_top_h = max(8, int(height * 0.58))
    left_bottom_h = height - left_top_h
    right_top_h = 7
    right_mid_h = max(9, int((height - right_top_h) * 0.58))
    right_bottom_h = height - right_top_h - right_mid_h

    draw_card(stdscr, 0, 1, left_top_h, left_w, "Port List", colors)
    draw_card(stdscr, left_top_h, 1, left_bottom_h, left_w, "LLM Response", colors)
    draw_card(stdscr, 0, right_x, right_top_h, right_w, "Attacks", colors)
    draw_card(stdscr, right_top_h, right_x, right_mid_h, right_w, "Logs with Threat Level", colors)
    draw_card(stdscr, right_top_h + right_mid_h, right_x, right_bottom_h, right_w, "Response (by ID)", colors)

    safe_addstr(stdscr, 1, 3, "PORT  HITS  ROLE", colors["title"])
    for idx, (port, hits, role) in enumerate(state.top_ports(count=max(1, left_top_h - 3))):
        row = 2 + idx
        if row >= left_top_h - 1:
            break
        safe_addstr(stdscr, row, 3, f"{port:<5} {hits:<5} {role}", colors["base"])

    backend_text = f"Backend: {state.debrief.get('backend', '-')}"
    backend_lines = add_wrapped_text(
        stdscr,
        left_top_h + 1,
        3,
        backend_text,
        width=max(10, left_w - 4),
        attr=colors["title"],
        max_lines=2,
    )
    level = str(state.debrief.get("level", "low")).lower()
    level_color = colors["ok"] if level == "low" else colors["warn"] if level in {"medium", "high"} else colors["danger"]
    level_row = left_top_h + 1 + backend_lines
    safe_addstr(stdscr, level_row, 3, f"Level: {level.upper()}", level_color)
    if state.last_report_generated_at is not None:
        ts = datetime.fromtimestamp(state.last_report_generated_at).strftime("%H:%M:%S")
        safe_addstr(stdscr, level_row, 16, f"Report @ {ts}", colors["dim"])
    elif state.current_attack_last_event_at is not None:
        safe_addstr(stdscr, level_row, 16, "Collecting current attack...", colors["dim"])
    llm_width = max(10, left_w - 4)
    used = add_wrapped_text(
        stdscr,
        level_row + 1,
        3,
        str(state.debrief.get("summary", "")),
        width=llm_width,
        attr=colors["base"],
        max_lines=max(1, left_bottom_h - 7),
    )
    row = level_row + 1 + used
    for item in state.debrief.get("actions", [])[:3]:
        if row >= height - 2:
            break
        consumed = add_wrapped_text(stdscr, row, 3, f"- {item}", width=llm_width, attr=colors["base"], max_lines=2)
        row += max(1, consumed)

    avg_threat = state.average_weighted_threat()
    avg_color = colors["ok"] if avg_threat < 20 else colors["warn"] if avg_threat < 50 else colors["danger"]
    safe_addstr(stdscr, 1, right_x + 2, f"Attacks (30s): {state.current_attack_count()}   Sources (60s): {state.active_source_count()}", colors["chip_warn"])
    safe_addstr(stdscr, 2, right_x + 2, f"Avg threat: {avg_threat:05.2f}/99   Total events: {state.total_events}", avg_color)
    safe_addstr(stdscr, 3, right_x + 2, f"Mode: {mode_label}   Uptime: {state.uptime()}", colors["base"])
    safe_addstr(stdscr, 4, right_x + 2, "Policy: 0-19 alert | 20-49 honeypot 15m | 50-99 honeypot 1h", colors["title"])

    safe_addstr(stdscr, right_top_h + 1, right_x + 2, "ID", colors["title"])
    safe_addstr(stdscr, right_top_h + 1, right_x + 7, "TIME", colors["title"])
    safe_addstr(stdscr, right_top_h + 1, right_x + 16, "SRC", colors["title"])
    safe_addstr(stdscr, right_top_h + 1, right_x + 32, "EVENT", colors["title"])
    safe_addstr(stdscr, right_top_h + 1, right_x + 49, "THREAT", colors["title"])
    safe_addstr(stdscr, right_top_h + 1, right_x + 58, "RESPONSE", colors["title"])

    mid_rows = max(1, right_mid_h - 3)
    logs = list(state.recent_logs)
    max_scroll = max(0, len(logs) - mid_rows)
    safe_scroll = max(0, min(log_scroll, max_scroll))
    visible_logs = logs[safe_scroll : safe_scroll + mid_rows]
    safe_addstr(stdscr, right_top_h + 1, right_x + right_w - 18, f"scroll {safe_scroll}/{max_scroll}", colors["dim"])
    for idx, log in enumerate(visible_logs):
        row = right_top_h + 2 + idx
        when = datetime.fromtimestamp(float(log["timestamp"])).strftime("%H:%M:%S")
        score = int(log["score"])
        response = str(log["response"])
        event_color = colors["ok"] if score < 20 else colors["warn"] if score < 50 else colors["danger"]
        safe_addstr(stdscr, row, right_x + 2, f"{int(log.get('id', 0)):03}", colors["dim"])
        safe_addstr(stdscr, row, right_x + 7, when, colors["base"])
        safe_addstr(stdscr, row, right_x + 16, f"{str(log['src_ip']):<15}", colors["base"])
        safe_addstr(stdscr, row, right_x + 32, f"{str(log['type']):<16}", event_color)
        safe_addstr(stdscr, row, right_x + 49, f"{score:02d}/99", event_color)
        safe_addstr(stdscr, row, right_x + 58, response, event_color)

    base_y = right_top_h + right_mid_h
    safe_addstr(stdscr, base_y + 1, right_x + 2, "Latest response actions (linked to log IDs):", colors["title"])
    action_rows = max(1, right_bottom_h - 3)
    row = base_y + 2
    for action in list(state.recent_actions):
        if row >= base_y + 2 + action_rows:
            break
        severity = str(action.get("severity", "low")).upper()
        src = str(action.get("src_ip", "-"))
        summary = str(action.get("summary", ""))
        enforcement = action.get("enforcement", {})
        if isinstance(enforcement, dict):
            applied = enforcement.get("applied")
            reason = enforcement.get("reason", "ok" if applied else "none")
            enf = f" [enf:{applied}/{reason}]"
        else:
            enf = ""
        color = colors["ok"] if severity == "LOW" else colors["warn"] if severity in {"MEDIUM", "HIGH"} else colors["danger"]
        consumed = add_wrapped_text(
            stdscr,
            row,
            right_x + 2,
            f"[{severity}] {src} -> {summary}{enf}",
            width=max(12, right_w - 4),
            attr=color,
            max_lines=2,
        )
        row += max(1, consumed)

    safe_addstr(stdscr, height - 1, 2, "q quit  c clear  j/k or arrows scroll logs  PgUp/PgDn  Home/End", colors["dim"])
    stdscr.refresh()


def run_dashboard(
    stdscr: curses.window,
    event_q: queue.Queue[dict[str, Any]],
    action_q: queue.Queue[dict[str, Any]],
    mode_label: str,
    log_file: Path,
) -> None:
    curses.curs_set(0)
    stdscr.nodelay(True)
    stdscr.timeout(100)
    colors = init_colors()
    state = DashboardState(log_file=log_file)
    debrief = LocalDebrief()
    log_scroll = 0

    while True:
        while True:
            try:
                state.add_event(event_q.get_nowait())
            except queue.Empty:
                break
        while True:
            try:
                state.recent_actions.appendleft(action_q.get_nowait())
            except queue.Empty:
                break

        closed_session = state.maybe_close_attack_session(idle_gap_seconds=8.0, min_events=4)
        if closed_session is not None:
            state.debrief = debrief.interpret(closed_session)
            state.last_report_generated_at = time.time()
        elif state.current_attack_last_event_at is not None:
            age = time.time() - state.current_attack_last_event_at
            if age < 8.0:
                state.debrief["summary"] = (
                    "Attack in progress. Capturing full session before generating report..."
                )

        render(stdscr, state, mode_label, colors, log_scroll)
        key = stdscr.getch()
        if key in (ord("q"), ord("Q")):
            return
        if key in (ord("c"), ord("C")):
            state = DashboardState(log_file=log_file)
            log_scroll = 0
            continue

        height, width = stdscr.getmaxyx()
        right_top_h = 7
        right_mid_h = max(9, int((height - right_top_h) * 0.58))
        mid_rows = max(1, right_mid_h - 3)
        max_scroll = max(0, len(state.recent_logs) - mid_rows)

        if key in (curses.KEY_DOWN, ord("j"), ord("J")):
            log_scroll = min(max_scroll, log_scroll + 1)
        elif key in (curses.KEY_UP, ord("k"), ord("K")):
            log_scroll = max(0, log_scroll - 1)
        elif key == curses.KEY_NPAGE:
            log_scroll = min(max_scroll, log_scroll + 5)
        elif key == curses.KEY_PPAGE:
            log_scroll = max(0, log_scroll - 5)
        elif key == curses.KEY_HOME:
            log_scroll = 0
        elif key == curses.KEY_END:
            log_scroll = max_scroll


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="GhostWall TUI dashboard")
    parser.add_argument("--live", action="store_true", help="Run full live stack in TUI (default mode)")
    parser.add_argument("--demo", action="store_true", help="Generate synthetic attack events")
    parser.add_argument("--stdin", action="store_true", help="Read event objects from stdin")
    parser.add_argument("--follow", type=Path, help="Tail a JSONL-like event file")
    parser.add_argument(
        "--interface",
        default=os.getenv("GHOSTWALL_INTERFACE", "eth0"),
        help="Interface for live scanner mode (example: wlp0s20f3, eth0, lo)",
    )
    parser.add_argument(
        "--listen-port",
        type=int,
        default=int(os.getenv("FSSH_LISTEN_PORT", "22")),
        help="fssh listen port (default: 22)",
    )
    parser.add_argument(
        "--real-ssh-port",
        type=int,
        default=int(os.getenv("FSSH_REAL_SSH_PORT", "47832")),
        help="Real SSH backend port for whitelisted users",
    )
    parser.add_argument(
        "--cowrie-port",
        type=int,
        default=int(os.getenv("DEFENSE_COWRIE_PORT", "2222")),
        help="Cowrie backend port for non-whitelisted users",
    )
    parser.add_argument(
        "--whitelist",
        default=os.getenv("FSSH_WHITELIST", ""),
        help="Comma-separated IP whitelist for real SSH routing",
    )
    parser.add_argument(
        "--force-honeypot",
        default=os.getenv("FSSH_FORCE_HONEYPOT", ""),
        help="Comma-separated IPs forced to Cowrie even if whitelisted",
    )
    parser.add_argument(
        "--cowrie-follow",
        type=Path,
        help="Tail Cowrie JSON log (default in live mode: ./cowrie-logs/cowrie.json)",
    )
    parser.add_argument(
        "--no-cowrie-follow",
        action="store_true",
        help="Disable Cowrie log follow in live mode",
    )
    parser.add_argument("--actions-follow", type=Path, help="Tail defense actions JSONL")
    parser.add_argument("--log-file", type=Path, default=Path("ghostwall_tui_logs.txt"), help="Write logs with IDs to text file")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    event_q: queue.Queue[dict[str, Any]] = queue.Queue()
    action_q: queue.Queue[dict[str, Any]] = queue.Queue()
    fssh_server: socket.socket | None = None
    live_mode = False

    selected = [args.live, args.demo, args.stdin, bool(args.follow)]
    if sum(bool(x) for x in selected) > 1:
        raise SystemExit("Pick one mode: --live OR --demo OR --stdin OR --follow <path>")

    mode_label = "live"
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
        live_mode = True
        fssh_server = start_live_source(args, event_q)
        mode_label = (
            f"live:{args.interface} "
            f"fssh:{args.listen_port} "
            f"real:{args.real_ssh_port} "
            f"cowrie:{args.cowrie_port} "
            f"force:{args.force_honeypot or '-'}"
        )

    cowrie_path = args.cowrie_follow
    if cowrie_path is None and not args.no_cowrie_follow and live_mode:
        cowrie_path = Path(os.getenv("COWRIE_JSON_PATH", str(PROJECT_ROOT / "cowrie-logs" / "cowrie.json")))
    if cowrie_path is not None:
        if str(cowrie_path).startswith("/path/to/"):
            raise SystemExit("Replace /path/to/cowrie.json with a real file path (example: /tmp/cowrie.json).")
        start_cowrie_source(cowrie_path, event_q)
        mode_label = f"{mode_label} + cowrie:{cowrie_path}"

    if args.actions_follow:
        start_actions_source(args.actions_follow, action_q)
        mode_label = f"{mode_label} + actions:{args.actions_follow}"

    try:
        curses.wrapper(run_dashboard, event_q, action_q, mode_label, args.log_file)
    except KeyboardInterrupt:
        return 0
    finally:
        if fssh_server is not None:
            try:
                fssh_server.close()
            except Exception:
                pass
        fssh.set_log_callback(None)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
