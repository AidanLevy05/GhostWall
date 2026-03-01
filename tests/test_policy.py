from __future__ import annotations

import unittest

from Defense_Solutions.policy import _nft_ssh_redirect_rule_command


class TestPolicyRedirectRule(unittest.TestCase):
    def test_loopback_target_uses_redirect(self) -> None:
        command = _nft_ssh_redirect_rule_command(target_host="127.0.0.1", target_port=2222)
        self.assertIn("redirect", command)
        self.assertIn(":2222", command)
        self.assertNotIn("dnat", command)

    def test_remote_target_uses_dnat(self) -> None:
        command = _nft_ssh_redirect_rule_command(target_host="192.0.2.10", target_port=2222)
        self.assertIn("dnat", command)
        self.assertIn("192.0.2.10:2222", command)
        self.assertNotIn("redirect", command)


if __name__ == "__main__":
    unittest.main()
