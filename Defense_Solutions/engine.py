"""Defense response dispatcher for GhostWall events."""

from __future__ import annotations

from typing import Any

from Defense_Solutions.FTP.ftp import FTPDefense
from Defense_Solutions.HTTP.http import HTTPDefense
from Defense_Solutions.SSH.ssh import SSHDefense

_ssh = SSHDefense()
_http = HTTPDefense()
_ftp = FTPDefense()


def build_defense_actions(event: dict[str, Any]) -> list[dict[str, Any]]:
    """Route one event through all defense modules and collect actions."""
    actions: list[dict[str, Any]] = []
    for module in (_ssh, _http, _ftp):
        actions.extend(module.evaluate(event))
    return actions
