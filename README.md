# SSH-Shield

**Autonomous SSH Defense Loop** – honeypot deception + live threat scoring + adaptive response.

> Built by Aidan, Lathe, Nick, Andrew

---

## What it does

SSH-Shield runs a two-container stack that watches an SSH honeypot in real time, computes a live **Threat Score (0–100)**, and triggers adaptive defenses automatically.

| Layer | Description |
|---|---|
| **Honeypot** | Cowrie SSH honeypot listens on host port **2222** – real SSH (port 22) is never exposed |
| **Collector** | Tails `cowrie.json`, normalises each event, writes to SQLite |
| **Scoring** | Sliding-window metrics → weighted score + exponential decay |
| **Defense** | Dry-run (default) or real `nftables` bans at ORANGE/RED levels |
| **Dashboard** | Single-page web UI at `http://localhost:8000` |

---

## Architecture

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
```

---

## Threat Levels

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

score = max(raw_score, prev_score × 0.97)   # decay
```

---

## Quick start

```bash
# 1. Clone and enter the repo
git clone <repo-url> && cd ssh-shield

# 2. Build and start everything
docker compose up --build

# 3. Open dashboard
open http://localhost:8000

# 4. Simulate an attack (from another terminal)
for i in $(seq 1 50); do
  ssh -p 2222 -o StrictHostKeyChecking=no root@localhost exit 2>/dev/null
  sleep 0.3
done
```

Watch the Threat Score climb from **GREEN → YELLOW → ORANGE/RED** on the dashboard.

---

## Project layout

```
.
├── docker-compose.yml        # Cowrie + app services
├── cowrie/
│   └── cowrie.cfg            # Honeypot config overrides
└── app/
    ├── Dockerfile
    ├── requirements.txt
    ├── main.py               # FastAPI entry point + background task launcher
    ├── collector.py          # Log tailer + event normaliser
    ├── db.py                 # SQLite helpers (events + snapshots tables)
    ├── models.py             # Pydantic models
    ├── scoring.py            # Metrics window + weighted threat score + decay
    ├── defense.py            # Adaptive defense module (dry-run / nftables)
    └── static/
        └── index.html        # Single-page dashboard UI
```

---

## API endpoints

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/` | Dashboard UI |
| `GET` | `/api/status` | Live threat status (score, level, why, actions, metrics) |
| `GET` | `/api/events` | Recent raw events from SQLite |
| `GET` | `/api/timeline` | Score snapshots for the timeline graph |
| `GET` | `/api/sessions` | Honeypot sessions grouped by session ID |

---

## Configuration

| Env var | Default | Description |
|---------|---------|-------------|
| `COWRIE_LOG_PATH` | `/cowrie-logs/cowrie.json` | Path to Cowrie JSON log (mounted read-only) |
| `DB_PATH` | `/data/shield.db` | SQLite database path |
| `DRY_RUN` | `true` | Set to `false` to enable real nftables enforcement |

---

## Responsible use

- The honeypot runs on **port 2222** only – real SSH (22) is never touched.
- Defense module defaults to **dry-run** – all bans are logged, not enforced, unless `DRY_RUN=false`.
- For production exposure, place behind a VPN or IP allowlist; never expose the honeypot port publicly without understanding the implications.
