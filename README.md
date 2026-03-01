# GhostWall

**A HenHacks Submission by Aidan L, Lathe E, Nicholas C, and Andrew X**

GhostWall is a **port-migration honeypot system** for cybersecurity professionals. It keeps your real services running while silently routing attackers into convincing fake ones — logging every move they make, wasting their time, and alerting you in real time.

If you value your security _and_ your uptime, trust **GhostWall**.

---

## How It Works

GhostWall sits in front of your SSH and FTP services. When a connection arrives it checks whether the source IP is whitelisted:

- **Whitelisted (legitimate users)** → forwarded transparently to the real service on a hidden port.
- **Everyone else** → silently redirected to a honeypot that looks identical to the real thing.

Meanwhile a background packet scanner watches the wire for ARP scans, port sweeps, and brute-force attempts and raises alerts as they happen.

```
Client                GhostWall                 Destination
  │                      │
  │──── connect :22 ────▶│
  │                      │── whitelisted? ──YES──▶ real SSH  (:47832)
  │                      │
  │                      │── whitelisted? ──NO───▶ Cowrie honeypot (:2222)
  │                      │
  │                      │── scanner sees SYN flood?
  │                      │       └──▶ defense_actions.jsonl event logged
```

---

## Features

| Feature | Status |
|---|---|
| SSH port redirection (real vs. honeypot) | ✅ |
| FTP port redirection (real vs. honeypot) | ✅ |
| FTP honeypot with fake file system | ✅ |
| SSH honeypot via Cowrie (Docker) | ✅ |
| HTTP/S probe detection (ports 80 / 443) | ✅ |
| Real-time packet scanner (ARP, sweep, brute-force) | ✅ |
| AI-scored defense events (`defense_actions.jsonl`) | ✅ |
| Auto-block policy mode | ✅ |
| Terminal UI | 🚧 In progress |
| LLM debrief chatbot | 🚧 In progress |

---

## Architecture

```
main.py  ──┬──▶  scanner.py          (Scapy packet capture — threat detection)
           ├──▶  Defense_Solutions/
           │       fport/redirector.py  (generic TCP proxy)
           │       fport/fssh.py        (SSH redirector, port 22)
           │       fport/fftp.py        (FTP redirector, port 21)
           │       FTP/ftp.py           (FTP honeypot, port 2121)
           │       SSH/  ─────────────▶ Cowrie container (ports 2222 / 2223)
           └──▶  defense_actions.jsonl  (append-only event log)
```

### Port map

| Port | Role |
|---|---|
| 22 | GhostWall redirector (SSH ingress — do not expose your real SSH here) |
| 21 | GhostWall redirector (FTP ingress) |
| 2222 / 2223 | Cowrie SSH honeypot (Docker) |
| 2121 | Built-in FTP honeypot |
| 47832 | Real SSH service (hidden) |
| 48291 | Real FTP service (hidden) |
| 80 / 443 | Monitored for HTTP probes and brute-force |

---

## Requirements

- Python 3.10+
- [`scapy`](https://scapy.net/) — `pip install scapy`
- Docker + Docker Compose (for Cowrie SSH honeypot)
- Root / `sudo` (required for raw packet capture and binding to privileged ports)

---

## Installation

```bash
git clone https://github.com/AidanLevy05/GhostWall.git
cd GhostWall
pip install scapy
```

For the Cowrie SSH honeypot:

```bash
docker compose up -d
```

---

## Configuration

All tunable constants live at the top of two files.

### `main.py`

```python
INTERFACE      = "eth0"       # network interface to monitor

WHITELIST      = ["127.0.0.1"]  # IPs routed to real services

REAL_SSH_PORT  = 47832        # where your actual SSH daemon listens
REAL_FTP_PORT  = 48291        # where your actual FTP daemon listens

HONEYPOT_SSH_PORT = 2222      # Cowrie container
HONEYPOT_FTP_PORT = 2121      # built-in FTP honeypot
```

### `scanner.py`

```python
ARP_THRESHOLD   = 5     # ARP requests within window → ARP scan alert
ARP_WINDOW      = 10    # seconds

SWEEP_THRESHOLD = 15    # distinct ports within window → port sweep alert
SWEEP_WINDOW    = 10

BRUTE_THRESHOLD = 10    # SYN packets on same port within window → brute-force alert
BRUTE_WINDOW    = 10

COOLDOWN        = 1     # seconds between duplicate alerts for the same source
```

---

## Running

```bash
sudo python3 main.py          # defaults to eth0
sudo python3 main.py wlan0    # specify an interface
```

Verify the listeners are up:

```bash
sudo ss -ltnp | grep -E ':22|:2222'
```

Expected output:

```
LISTEN  0  10    0.0.0.0:22    0.0.0.0:*  users:(("python3",...))
LISTEN  0  4096  0.0.0.0:2222  0.0.0.0:*  users:(("docker-proxy",...))
```

---

## Defense Action Log

Every detected event is appended to `defense_actions.jsonl` as a newline-delimited JSON record.

```jsonc
{
  "event_type":  "brute.force",          // connect.attempt | brute.force | sweep | arp.scan
  "source":      "http",                 // ssh/cowrie | http | ftp | arp
  "src_ip":      "172.20.10.3",
  "summary":     "High-rate brute-force signature on web port 80 from 172.20.10.3.",
  "severity":    "high",                 // low | medium | high
  "confidence":  0.9,                    // 0.0 – 1.0
  "tags":        ["http", "bruteforce"],
  "commands":    ["rotate or lock targeted account paths",
                  "tighten WAF challenge policy for source cohort"],
  "policy_mode": "auto-block",
  "enforcement": { "applied": false, "reason": "no_mitigation" },
  "recommended": true,
  "created_at":  1772339663.2319465      // Unix timestamp
}
```

Tail the log in real time:

```bash
tail -f defense_actions.jsonl | python3 -m json.tool
```

---

## Project Structure

```
GhostWall/
├── main.py                        # entry point — wires everything together
├── scanner.py                     # Scapy-based threat detector
├── test.py                        # utility: dump /etc/services to CSV
├── defense_actions.jsonl          # runtime event log (git-ignored)
├── cowrie-logs/                   # Cowrie output (git-ignored)
│   └── cowrie.json
├── Defense_Solutions/
│   ├── fport/
│   │   ├── redirector.py          # generic TCP proxy base class
│   │   ├── fssh.py                # SSH redirector (port 22)
│   │   └── fftp.py                # FTP redirector (port 21)
│   ├── FTP/
│   │   └── ftp.py                 # fake FTP server (port 2121)
│   ├── SSH/
│   │   └── ssh.py                 # SSH honeypot stub
│   └── HTTP/
│       └── http.py                # HTTP honeypot stub
├── TUI/
│   └── graphics.py                # terminal UI (in progress)
└── LLM_Debrief/
    └── chatbot.py                 # AI debrief assistant (in progress)
```

---

## Detection Types

| Threat | Trigger | Severity |
|---|---|---|
| ARP scan | ≥ 5 ARP requests in 10 s | medium |
| Port sweep | ≥ 15 distinct ports in 10 s | medium |
| SSH brute-force | ≥ 10 SYN packets on port 22 in 10 s | high |
| HTTP probe | Repeated connections to port 80/443 | low |
| HTTP brute-force | High-rate HTTP signature | high |

---

## Team

| Name | GitHub |
|---|---|
| Aidan L | [@AidanLevy05](https://github.com/AidanLevy05) |
| Lathe E | — |
| Nicholas C | — |
| Andrew X | — |

---

*Built at HenHacks.*
