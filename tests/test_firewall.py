import unittest

from remnawave_node.firewall import build_iptables_plan, build_nft_plan, build_ufw_plan


class FirewallTests(unittest.TestCase):
    def test_ufw_restricts_node_to_panel(self):
        plan = build_ufw_plan(["203.0.113.10"], 22)
        commands = [" ".join(command) for command in plan.commands]
        self.assertTrue(any("from 203.0.113.10" in command and "2222" in command for command in commands))
        self.assertFalse(any("9443" in command and "allow" in command for command in commands))

    def test_no_destructive_commands(self):
        for plan in (build_nft_plan([], 22), build_iptables_plan([], 22)):
            flattened = " ".join(" ".join(command) for command in plan.commands)
            self.assertNotIn("flush ruleset", flattened)
            self.assertNotIn("-F", flattened)

    def test_empty_panel_ips_warn(self):
        self.assertTrue(build_ufw_plan([], 22).warnings)


if __name__ == "__main__":
    unittest.main()
