import unittest

from remnawave_node.firewall import apply_plan, build_iptables_plan, build_nft_plan, build_ufw_plan, detect_backend
from remnawave_node.system import CommandResult


class FakeRunner:
    def __init__(self):
        self.commands = []

    def run(self, args, **kwargs):
        self.commands.append(args)
        return CommandResult(0, "")


class UfwStatusRunner(FakeRunner):
    def run(self, args, **kwargs):
        self.commands.append(args)
        if args == ["ufw", "status"]:
            return CommandResult(0, "Status: active\n8080/tcp ALLOW IN Anywhere\n2222/tcp ALLOW IN 203.0.113.10\n")
        return CommandResult(0, "")


class BackendRunner:
    def __init__(self, nft_json="{}"):
        self.nft_json = nft_json

    def exists(self, command):
        return command in {"nft", "iptables"}

    def run(self, args, **kwargs):
        if args == ["nft", "list", "ruleset"]:
            return CommandResult(0, "table ip filter { chain FORWARD {} }")
        if args == ["nft", "-j", "list", "ruleset"]:
            return CommandResult(0, self.nft_json)
        return CommandResult(0, "")


class FailingRunner(FakeRunner):
    def __init__(self, fail_at):
        super().__init__()
        self.fail_at = fail_at

    def run(self, args, **kwargs):
        self.commands.append(args)
        if len(self.commands) == self.fail_at:
            raise RuntimeError("simulated firewall failure")
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
        plan = build_iptables_plan(["203.0.113.10", "2001:db8::10"], 22)
        commands = [" ".join(command) for command in plan.commands]
        self.assertTrue(any("--dport 2222 -j ACCEPT" in command for command in commands))
        self.assertFalse(any("--dport 22 " in command or "80,443" in command for command in commands))
        self.assertTrue(any(command.startswith("ip6tables ") and "2001:db8::10" in command for command in commands))
        self.assertFalse(any(command.startswith("iptables ") and "2001:db8::10" in command for command in commands))
        self.assertEqual(plan.identifiers, ["iptables:REMNAWAVE_NODE:2222", "ip6tables:REMNAWAVE_NODE6:2222"])

    def test_ufw_does_not_open_ssh(self):
        plan = build_ufw_plan(["203.0.113.10"], 22)
        commands = [" ".join(command) for command in plan.commands]
        self.assertFalse(any("ssh" in command or "22/tcp" in command for command in commands))
        self.assertNotIn("ufw:base:22", plan.identifiers)

    def test_partial_apply_reports_created_chain_before_failure(self):
        runner = FailingRunner(fail_at=4)
        created = []
        with self.assertRaises(RuntimeError):
            apply_plan(build_iptables_plan(["203.0.113.10"], 22), runner, on_created=created.append)
        self.assertIn("iptables:REMNAWAVE_NODE:2222", created)

    def test_ufw_source_rule_has_correct_rollback_identifier(self):
        runner = FakeRunner()
        created = apply_plan(build_ufw_plan(["203.0.113.10"], 22), runner)
        self.assertIn("ufw:203.0.113.10:2222", created)

    def test_ufw_matching_does_not_treat_8080_as_port_80(self):
        runner = UfwStatusRunner()
        apply_plan(build_ufw_plan(["203.0.113.10"], 22), runner)
        self.assertIn(["ufw", "allow", "80/tcp", "comment", "remnawave-node http"], runner.commands)

    def test_nft_rules_without_native_input_chain_fall_back_to_iptables(self):
        self.assertEqual(detect_backend(BackendRunner()), "iptables")

    def test_native_inet_input_chain_selects_nftables(self):
        payload = '{"nftables":[{"chain":{"family":"inet","table":"filter","name":"input","type":"filter","hook":"input","prio":0,"policy":"accept"}}]}'
        self.assertEqual(detect_backend(BackendRunner(payload)), "nftables")

    def test_empty_panel_ips_warn(self):
        self.assertTrue(build_ufw_plan([], 22).warnings)


if __name__ == "__main__":
    unittest.main()
