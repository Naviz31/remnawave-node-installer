import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from remnawave_node import cli, ssh_guard


class Runner:
    def __init__(self, sshd_ok=True, tools=("sshd", "sysctl", "fail2ban-client")):
        self.calls = []
        self.sshd_ok = sshd_ok
        self.tools = tools

    def exists(self, command):
        return command in self.tools

    def run(self, args, check=True, timeout=0, **kwargs):
        self.calls.append(list(args))
        code = 1 if (list(args) == ["sshd", "-t"] and not self.sshd_ok) else 0
        return SimpleNamespace(returncode=code, stdout="", stderr="")


class GuardCase(unittest.TestCase):
    def setUp(self):
        root = Path(tempfile.mkdtemp())
        self.sshd = root / "ssh" / "90-remnawave-node.conf"
        self.sysctl = root / "sysctl" / "90-remnawave-node.conf"
        self.f2b = root / "f2b" / "remnawave-node.conf"
        for patcher in (mock.patch.object(ssh_guard, "SSHD_HARDENING_CONFIG", self.sshd), mock.patch.object(ssh_guard, "SYSCTL_CONFIG", self.sysctl),
                        mock.patch.object(ssh_guard, "FAIL2BAN_CONFIG", self.f2b)):
            patcher.start()
            self.addCleanup(patcher.stop)


class SshGuardTests(GuardCase):
    def test_fail2ban_jail_has_growing_bans(self):
        runner = Runner()
        self.assertTrue(ssh_guard.configure_fail2ban(runner))
        text = self.f2b.read_text()
        for expected in ("maxretry = 5", "bantime = 1h", "bantime.increment = true", "bantime.maxtime = 7d", "backend = systemd"):
            self.assertIn(expected, text)

    def test_ssh_limits_are_written_validated_and_reloaded(self):
        created, runner = [], Runner()
        self.assertTrue(ssh_guard.configure_ssh_limits(runner, on_created=created.append))
        text = self.sshd.read_text()
        self.assertIn("MaxStartups 60:30:200", text)
        self.assertNotIn("PasswordAuthentication", text)  # authentication methods are never touched
        self.assertNotIn("AllowUsers", text)
        self.assertEqual(created, [self.sshd])
        self.assertEqual(runner.calls[0], ["sshd", "-t"])
        self.assertIn(["systemctl", "reload", "ssh"], runner.calls)

    def test_invalid_sshd_config_is_rolled_back(self):
        self.assertFalse(ssh_guard.configure_ssh_limits(Runner(sshd_ok=False)))
        self.assertFalse(self.sshd.exists())
        self.sshd.parent.mkdir(parents=True, exist_ok=True)
        self.sshd.write_text("old\n")
        self.assertFalse(ssh_guard.configure_ssh_limits(Runner(sshd_ok=False)))
        self.assertEqual(self.sshd.read_text(), "old\n")

    def test_no_sshd_means_no_changes(self):
        self.assertFalse(ssh_guard.configure_ssh_limits(Runner(tools=())))
        self.assertFalse(self.sshd.exists())

    def test_kernel_protection_applies_syncookies(self):
        runner = Runner()
        self.assertTrue(ssh_guard.configure_kernel_protection(runner))
        self.assertIn("net.ipv4.tcp_syncookies = 1", self.sysctl.read_text())
        self.assertIn(["sysctl", "-p", str(self.sysctl)], runner.calls)
        self.assertFalse(ssh_guard.configure_kernel_protection(Runner(tools=())) )


class HardenCommandTests(GuardCase):
    def test_harden_runs_all_three_and_leaves_auth_alone(self):
        runner = Runner()
        with mock.patch.object(cli, "_root_check"), mock.patch.object(cli, "_runner", return_value=runner):
            self.assertEqual(cli.main(["harden"]), 0)
        self.assertTrue(self.f2b.exists() and self.sshd.exists() and self.sysctl.exists())

    def test_harden_is_idempotent(self):
        runner = Runner()
        with mock.patch.object(cli, "_root_check"), mock.patch.object(cli, "_runner", return_value=runner):
            cli.main(["harden"])
            before = (self.f2b.read_text(), self.sshd.read_text(), self.sysctl.read_text())
            cli.main(["harden"])
        self.assertEqual(before, (self.f2b.read_text(), self.sshd.read_text(), self.sysctl.read_text()))


if __name__ == "__main__":
    unittest.main()
