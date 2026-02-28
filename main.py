"""
GhostWall — Honeypot Defense System
=====================================
Entry point. Starts the Textual TUI which owns the asyncio event loop.
Background tasks (scanner, scoring, defense) are launched from on_mount.

Usage:
    sudo python3 main.py

Ports 22, 21, and 23 require root or CAP_NET_BIND_SERVICE.
To grant without running as root:
    sudo setcap 'cap_net_bind_service=+ep' $(which python3)
    python3 main.py

Environment variables:
    DB_PATH           Path to SQLite database   (default: ./ghostwall.db)
    DRY_RUN           'false' to enable real nftables enforcement (default: true)
    ANTHROPIC_API_KEY Set to enable LLM debrief (optional)
"""
import logging

# Log to file so output doesn't interfere with the TUI
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s - %(message)s",
    handlers=[logging.FileHandler("ghostwall.log", mode="a")],
)

from TUI import GhostWallApp


def main() -> None:
    app = GhostWallApp()
    app.run()


if __name__ == "__main__":
    main()
