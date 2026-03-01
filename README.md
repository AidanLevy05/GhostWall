# GhostWall

**Autonomous Multi-Protocol Defense System** – honeypot deception + live threat scoring + adaptive response.

> Built by Aidan, Lathe, Nick, Andrew

---

## What it does

GhostWall detects and responds to network attacks across SSH, HTTP, and FTP. It has **two runtime modes** that can be used independently or together:

| Mode | Description |
|---|---|
| **Docker stack** | Two-container setup (Cowrie honeypot + FastAPI app) that watches Cowrie's JSON log, scores threats, and serves a web dashboard |
| **Native runtime** | Standalone Python process that sniffs packets with Scapy, runs a fake SSH proxy (fssh) that transparently routes attackers to Cowrie, and displays a live curses TUI with LLM-powered debrief |

---

## Docker Stack Architecture

```
  Attacker
     │  SSH (port 2222)
     ▼
┌────────────────────┐       shared Docker volume
│  cowrie container  │──── cowrie.json ────────────────────┐
│  (SSH honeypot)    │                                      │
└────────────────────┘                                      │
                                                            ▼
                                               ┌────────────────────────┐
                                               │     app container      │
                                               │  ┌──────────────────┐  │
                                               │  │  collector task  │  │ tails log → SQLite
                                               │  └──────────────────┘  │
                                               │  ┌──────────────────┐  │
                                               │  │  scoring loop    │  │ metrics window → score
                                               │  └──────────────────┘  │
                                               │  ┌──────────────────┐  │
                                               │  │  defense loop    │  │ dry-run bans / nftables
                                               │  └──────────────────┘  │
                                               │  ┌──────────────────┐  │
                                               │  │  FastAPI server  │  │──► http://localhost:8000
                                               │  └──────────────────┘  │
                                               └────────────────────────┘
                                                            ▲
                                               ┌────────────┴───────────┐
                                               │  tui.py (optional)     │ Textual TUI connecting
                                               │  (runs on host)        │ to FastAPI via HTTP
                                               └────────────────────────┘
```

### Docker stack layers

| Layer | Description |
|---|---|
| **Honeypot** | Cowrie SSH honeypot on host port **2222** |
| **Collector** | Tails `cowrie.json`, normalises each event, writes to SQLite |
| **Scoring** | Sliding-window metrics → weighted score + exponential decay |
| **Defense** | Dry-run (default) or real `nftables` bans at ORANGE/RED levels |
| **Dashboard** | Single-page web UI at `http://localhost:8000` |
| **tui.py** | Optional Textual terminal UI that polls the FastAPI backend |

---

## Native Runtime Architecture

```
  Attacker
     │  SSH (port 22 — fake SSH proxy)
     ▼
┌─────────────────────────────────────────────────────┐
│                     fssh proxy                       │
│  whitelisted IPs ──► real SSH (port 47832)           │
│  everyone else  ──► Cowrie (port 2222)               │
│  blacklisted    ──► connection dropped               │
└─────────────────────────────────────────────────────┘

  Network interface (Scapy)
     │  ARP requests, TCP SYN, port sweeps, brute force
     ▼
┌─────────────────┐     ┌───────────────────────────┐
│   scanner.py    │────►│  Defense_Solutions/engine  │
│ (Scapy sniffer) │     │  SSH / HTTP / FTP modules  │
└─────────────────┘     └───────────────────────────┘
                                    │
                         ┌──────────┴──────────┐
                         │   DefensePolicy      │
                         │  detect (default)    │
                         │  auto-block (nft)    │
                         └──────────────────────┘
                                    │
                         ┌──────────▼──────────┐
                         │   TUI/tui.py         │
                         │  curses dashboard    │
                         │  + LLM debrief       │
                         └──────────────────────┘
```

### Native runtime components

| Component | Description |
|---|---|
| **fssh** | Fake SSH proxy on port 22 — whitelisted IPs reach real SSH, everyone else hits Cowrie; attackers are added to a persistent blacklist |
| **scanner.py** | Scapy packet sniffer — detects ARP scans, port sweeps, and brute-force SYN floods |
| **Defense engine** | SSH, HTTP, and FTP defense modules evaluate events and produce mitigation actions |
| **DefensePolicy** | `detect` mode logs actions; `auto-block` mode enforces them via nftables |
| **FTP honeypot** | Fake vsFTPd server on port 2121 — emulates a directory of enticing files and stalls download attempts |
| **TUI/tui.py** | Curses terminal dashboard showing live events, port stats, threat scores, and LLM debrief |
| **LLM_Debrief** | Post-attack analysis via local Ollama (default model: `llama3.2:3b`) with heuristic fallback |

---

## Threat Levels (Docker Stack / Scoring)

| Score | Level  | Color  | Response |
|-------|--------|--------|----------|
| 0–25  | GREEN  | 🟢     | Monitor only |
| 26–50 | YELLOW | 🟡     | Rate limiting logged |
| 51–74 | ORANGE | 🟠     | Top offenders temp-banned (60 s) |
| 75–100| RED    | 🔴     | Extended bans (300 s) + tighter rate limits |

### Score formula

```
score = Σ ( min(metric / cap, 1.0) × weight ) × 100

metric          weight  cap
─────────────────────────────
fail_rate        0.40   30 / 60s
conn_rate        0.25   20 / 60s
unique_ips       0.20   15 / 10min
repeat_offenders 0.10   10 / 1h
ban_events       0.05   5  / 10min

score = max(raw_score, prev_score × 0.998)   # per 5-second interval
```

---

## Quick start

### Option A — Docker stack

```bash
# 1. Clone and enter the repo
git clone <repo-url> && cd GhostWall

# 2. Build and start everything
docker compose up --build

# 3. Open dashboard
open http://localhost:8000

# 4. (Optional) run the Textual TUI
pip install textual httpx
python3 tui.py

# 5. Simulate an attack (from another terminal)
for i in $(seq 1 50); do
  ssh -p 2222 -o StrictHostKeyChecking=no root@localhost exit 2>/dev/null
  sleep 0.3
done
```

### Option B — Native runtime (requires root + Scapy)

```bash
# 1. Install dependencies
pip install -r requirements-tui.txt   # for TUI
# scapy also required for scanner

# 2. Move real SSH off port 22 first (example: port 47832)

# 3. Run the TUI (packet sniffing + fssh + curses dashboard)
./run.sh
```

`run.sh` sets all required env vars and launches `TUI/tui.py`:

```bash
sudo DEFENSE_MODE=auto-block DEFENSE_FIREWALL_BACKEND=nftables \
  FSSH_WHITELIST="172.20.10.3,127.0.0.1" FSSH_FORCE_HONEYPOT="172.20.10.3" \
  venv/bin/python3 TUI/tui.py --interface wlp0s20f3 \
  --listen-port 22 --real-ssh-port 47832 --cowrie-port 2222 --reset-blacklist
```

Edit `run.sh` to change the interface (`wlp0s20f3`), whitelist IPs, or other defaults before running.

---

## Project layout

```
.
├── docker-compose.yml          # Cowrie + app containers
├── cowrie/
│   └── cowrie.cfg              # Honeypot config overrides
├── app/
│   ├── Dockerfile
│   ├── requirements.txt
│   ├── main.py                 # FastAPI entry point + background task launcher
│   ├── collector.py            # Log tailer + event normaliser
│   ├── db.py                   # SQLite helpers (events + snapshots tables)
│   ├── models.py               # Pydantic models
│   ├── scoring.py              # Metrics window + weighted threat score + decay
│   ├── defense.py              # Adaptive defense module (dry-run / nftables)
│   └── static/
│       └── index.html          # Single-page dashboard UI
├── tui.py                      # Textual TUI — connects to FastAPI backend
├── main.py                     # Native runtime orchestrator (fssh + scanner + defense)
├── scanner.py                  # Scapy packet sniffer (ARP, port sweep, brute force)
├── defense_runner.py           # Scanner + defense engine, no TUI
├── handler.py                  # Port config utility
├── Defense_Solutions/
│   ├── engine.py               # Routes events through all defense modules
│   ├── policy.py               # DefensePolicy: detect / auto-block + nftables execution
│   ├── common.py               # Shared helpers (CooldownGate, make_action)
│   ├── SSH/ssh.py              # SSH defense module (Cowrie redirect on spray)
│   ├── HTTP/http.py            # HTTP/S defense module (rate limit on spray)
│   ├── FTP/ftp.py              # FTP defense module + FTP honeypot (port 2121)
│   └── fport/fssh.py           # Fake SSH proxy (port routing + blacklist)
├── TUI/
│   └── tui.py                  # Curses-based live dashboard + LLM debrief
├── LLM_Debrief/
│   └── chatbot.py              # Ollama / heuristic post-attack debrief
├── cowrie-logs/
│   └── cowrie.json             # Cowrie JSON log (shared volume mount point)
├── simulate_attack.py          # Attack traffic simulator for local testing
├── run.sh                      # Full native runtime launch (auto-block mode)
├── run_local.sh                # Local backend without Docker
├── req.txt                     # Native runtime dependencies
└── requirements-tui.txt        # Textual TUI dependencies
```

---

## API endpoints

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/` | Dashboard UI |
| `GET` | `/api/status` | Live threat status (score, level, why, actions, metrics, top IPs, top usernames) |
| `GET` | `/api/events` | Recent raw events from SQLite |
| `GET` | `/api/timeline` | Score snapshots for the timeline graph |
| `GET` | `/api/sessions` | Honeypot sessions grouped by session ID (last 24 h) |
| `POST` | `/api/score/reset` | Manually reset threat score to 0 |

---

## Configuration

### Docker stack environment variables

| Env var | Default | Description |
|---------|---------|-------------|
| `COWRIE_LOG_PATH` | `/cowrie-logs/cowrie.json` | Path to Cowrie JSON log (mounted read-only) |
| `DB_PATH` | `/data/shield.db` | SQLite database path |
| `DRY_RUN` | `true` | Set to `false` to enable real nftables enforcement |

### Native runtime environment variables

| Env var | Default | Description |
|---------|---------|-------------|
| `DEFENSE_MODE` | `detect` | `detect` = log actions only; `auto-block` = enforce via nftables |
| `DEFENSE_FIREWALL_BACKEND` | `nftables` | Firewall backend for enforcement |
| `FSSH_LISTEN_PORT` | `22` | Port the fake SSH proxy binds |
| `FSSH_REAL_SSH_PORT` | `47832` | Port real SSH is running on (for whitelisted IPs) |
| `FSSH_WHITELIST` | `` | Comma-separated IPs routed to real SSH |
| `FSSH_FORCE_HONEYPOT` | `` | Comma-separated IPs forced to Cowrie even if whitelisted |
| `FSSH_BLACKLIST_FILE` | `fssh_blacklist.txt` | Persistent blacklist path |
| `DEFENSE_COWRIE_PORT` | `2222` | Cowrie port for SSH redirect |
| `GHOSTWALL_LLM_BACKEND` | `heuristic` | `heuristic` or `ollama` for post-attack debrief |
| `GHOSTWALL_LLM_MODEL` | `llama3.2:3b` | Ollama model name |

---

## Responsible use

- The fake SSH proxy (`fssh`) listens on port 22 and transparently forwards traffic — move real SSH to another port (e.g. 47832) before starting the native runtime.
- The Cowrie honeypot runs on **port 2222** only.
- The defense module defaults to **dry-run / detect** – all bans are logged, not enforced, unless `DRY_RUN=false` (Docker) or `DEFENSE_MODE=auto-block` (native runtime).
- For production exposure, place behind a VPN or IP allowlist; never expose honeypot ports publicly without understanding the implications.
