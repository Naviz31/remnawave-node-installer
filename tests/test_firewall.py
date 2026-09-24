import unittest

from remnawave_node.firewall import apply_plan, build_iptables_plan, build_nft_plan, build_ufw_plan
from remnawave_node.system import CommandResult


class FakeRunner:
    def __init__(self):
        self.commands = []

    def run(self, args, **kwargs):
        self.commands.append(args)
        return CommandResult(0, "")


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

    def test_iptables_does_not_accept_unrelated_ports(self):
        plan = build_iptables_plan(["203.0.113.10"], 22)
        commands = [" ".join(command) for command in plan.commands]
        self.assertTrue(any("--dport 2222 -j ACCEPT" in command for command in commands))
        self.assertFalse(any("--dport 22 " in command or "80,443" in command for command in commands))
        self.assertEqual(plan.identifiers, ["iptables:REMNAWAVE_NODE:2222"])

    def test_ufw_source_rule_has_correct_rollback_identifier(self):
        runner = FakeRunner()
        created = apply_plan(build_ufw_plan(["203.0.113.10"], 22), runner)
        self.assertIn("ufw:203.0.113.10:2222", created)

    def test_empty_panel_ips_warn(self):
        self.assertTrue(build_ufw_plan([], 22).warnings)


if __name__ == "__main__":
    unittest.main()
