#!/usr/bin/env python3
"""
GhostWall – entry point.

Run with:
    sudo python main.py          # local (needs root for ports 21/22/23)
    docker-compose up --build    # via Docker
"""
import logging
logging.basicConfig(level=logging.WARNING)

from TUI.dashboard import GhostWallApp

if __name__ == "__main__":
    GhostWallApp().run()
