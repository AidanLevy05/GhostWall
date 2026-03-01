from __future__ import annotations

import unittest

from TUI.tui import DashboardState


class TestTuiThreatScoring(unittest.TestCase):
    def test_ssh_burst_escalates_score_and_average(self) -> None:
        state = DashboardState(log_file=None, trusted_sources=set())
        src = "203.0.113.42"
        base_ts = 1000.0

        for idx in range(20):
            state.add_event(
                {
                    "type": "connect.attempt",
                    "src_ip": src,
                    "port": 22,
                    "timestamp": base_ts + idx,
                }
            )

        latest = int(state.recent_logs[0]["score"])
        self.assertGreaterEqual(latest, 50)
        self.assertGreaterEqual(state.average_weighted_threat(), 40.0)

    def test_port_sweep_connect_burst_escalates_score(self) -> None:
        state = DashboardState(log_file=None, trusted_sources=set())
        src = "198.51.100.12"
        base_ts = 2000.0

        for idx in range(25):
            state.add_event(
                {
                    "type": "connect.attempt",
                    "src_ip": src,
                    "port": 1000 + idx,
                    "timestamp": base_ts + idx * 0.2,
                }
            )

        latest = int(state.recent_logs[0]["score"])
        self.assertGreaterEqual(latest, 55)
        self.assertGreaterEqual(state.average_weighted_threat(), 40.0)


if __name__ == "__main__":
    unittest.main()
