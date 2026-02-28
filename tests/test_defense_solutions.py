from __future__ import annotations

import unittest

from Defense_Solutions.FTP.ftp import FTPDefense
from Defense_Solutions.HTTP.http import HTTPDefense
from Defense_Solutions.SSH.ssh import SSHDefense
from Defense_Solutions.engine import build_defense_actions


class TestDefenseSolutions(unittest.TestCase):
    def test_engine_action_shape(self) -> None:
        event = {
            "type": "connect.attempt",
            "src_ip": "10.1.1.9",
            "port": 22,
            "timestamp": 1000.0,
        }
        actions = build_defense_actions(event)
        self.assertGreaterEqual(len(actions), 1)
        action = actions[0]
        self.assertIn(action["severity"], {"low", "medium", "high", "critical"})
        self.assertIsInstance(action["commands"], list)
        self.assertEqual(action["src_ip"], "10.1.1.9")

    def test_engine_dedup_same_event(self) -> None:
        event = {
            "type": "connect.attempt",
            "src_ip": "10.1.1.10",
            "port": 22,
            "timestamp": 2000.0,
        }
        first = build_defense_actions(event)
        second = build_defense_actions(event)
        self.assertGreater(len(first), 0)
        self.assertEqual(second, [])

    def test_ssh_escalation(self) -> None:
        defense = SSHDefense()
        src = "192.168.1.100"
        all_actions = []
        for i in range(1, 11):
            out = defense.evaluate(
                {
                    "type": "connect.attempt",
                    "src_ip": src,
                    "port": 22,
                    "timestamp": 3000.0 + i * 2.0,
                }
            )
            all_actions.extend(out)
        self.assertTrue(any(a["severity"] in {"high", "critical"} for a in all_actions))

    def test_http_sweep_detection(self) -> None:
        defense = HTTPDefense()
        out = defense.evaluate(
            {
                "type": "port.sweep",
                "src_ip": "172.16.0.5",
                "ports": [21, 22, 80, 443],
                "timestamp": 4000.0,
            }
        )
        self.assertTrue(any(a["source"] == "http" and a["severity"] == "medium" for a in out))

    def test_ftp_bruteforce(self) -> None:
        defense = FTPDefense()
        out = defense.evaluate(
            {
                "type": "brute.force",
                "src_ip": "172.16.0.6",
                "port": 21,
                "timestamp": 5000.0,
            }
        )
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0]["source"], "ftp")
        self.assertEqual(out[0]["severity"], "high")


if __name__ == "__main__":
    unittest.main()
