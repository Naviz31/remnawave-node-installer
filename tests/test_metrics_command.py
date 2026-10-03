import unittest
from unittest import mock

from remnawave_node import cli
from remnawave_node.errors import InstallerError


class MetricsCommandTests(unittest.TestCase):
    def setUp(self):
        self.state = {"metrics_ips": ["198.51.100.5"], "status": "installed"}
        patches = [
            mock.patch.object(cli, "_load_state", lambda: dict(self.state)),
            mock.patch.object(cli, "_runner", lambda: object()),
            mock.patch.object(cli, "_root_check", lambda: None),
            mock.patch.object(cli, "_print_metrics_info", mock.Mock()),
        ]
        for p in patches:
            p.start()
            self.addCleanup(p.stop)

    def test_show_without_ip_does_not_touch_firewall(self):
        with mock.patch.object(cli, "repair") as repair:
            self.assertEqual(cli.metrics_command(None), 0)
        repair.assert_not_called()
        cli._print_metrics_info.assert_called_once()

    def test_new_ip_runs_transactional_repair_with_override(self):
        with mock.patch.object(cli, "repair", return_value=0) as repair:
            self.assertEqual(cli.metrics_command("203.0.113.9, 203.0.113.10"), 0)
        repair.assert_called_once_with(metrics_ips_override=["203.0.113.9", "203.0.113.10"])

    def test_same_ip_is_a_noop(self):
        with mock.patch.object(cli, "repair") as repair:
            self.assertEqual(cli.metrics_command("198.51.100.5"), 0)
        repair.assert_not_called()

    def test_invalid_ip_is_rejected_before_any_change(self):
        with mock.patch.object(cli, "repair") as repair:
            with self.assertRaises(InstallerError):
                cli.metrics_command("not-an-ip")
        repair.assert_not_called()

    def test_metrics_must_have_been_enabled(self):
        self.state["metrics_ips"] = []
        with self.assertRaises(InstallerError):
            cli.metrics_command("203.0.113.9")

    def test_parser_and_dispatch(self):
        args = cli._parser().parse_args(["metrics", "--ip", "203.0.113.9"])
        self.assertEqual((args.command, args.ip), ("metrics", "203.0.113.9"))
        with mock.patch.object(cli, "metrics_command", return_value=0) as command:
            self.assertEqual(cli.main(["metrics", "--ip", "203.0.113.9"]), 0)
        command.assert_called_once_with("203.0.113.9", False)


class EnableMetricsTests(unittest.TestCase):
    def setUp(self):
        self.state = {"status": "installed", "node_port": 2222, "installed_packages": ["nginx"], "created_paths": [], "backups": []}
        self.calls = []
        patches = [
            mock.patch.object(cli, "_load_state", lambda: __import__("copy").deepcopy(self.state)),
            mock.patch.object(cli, "_runner", lambda: mock.Mock()),
            mock.patch.object(cli, "_root_check", lambda: None),
            mock.patch.object(cli, "_print_metrics_info", mock.Mock()),
            mock.patch("remnawave_node.state.StateStore.save", lambda self_, data: None),
            mock.patch("remnawave_node.state.Path.mkdir", lambda *a, **k: None),
        ]
        for p in patches:
            p.start()
            self.addCleanup(p.stop)

    def test_enable_opens_firewall_first_then_installs_exporter(self):
        order = []
        with mock.patch.object(cli, "repair", side_effect=lambda **kw: order.append(("repair", kw["metrics_ips_override"])) or 0), \
                mock.patch("remnawave_node.install.install_metrics_exporter_package", lambda runner, tx: order.append("package")), \
                mock.patch("remnawave_node.metrics.configure_node_exporter", lambda runner: order.append("configure")):
            self.assertEqual(cli.metrics_command("203.0.113.9", True), 0)
        self.assertEqual(order, [("repair", ["203.0.113.9"]), "package", "configure"])

    def test_failed_exporter_install_rolls_the_firewall_back(self):
        calls = []
        with mock.patch.object(cli, "repair", side_effect=lambda **kw: calls.append(kw["metrics_ips_override"]) or 0), \
                mock.patch("remnawave_node.install.install_metrics_exporter_package", side_effect=RuntimeError("apt failed")), \
                mock.patch("remnawave_node.state.InstallTransaction.restore_backups", lambda self_: None):
            with self.assertRaises(InstallerError) as raised:
                cli.metrics_command("203.0.113.9", True)
        self.assertEqual(calls, [["203.0.113.9"], []])  # rules added, then removed again
        self.assertIn("изменения отменены", str(raised.exception))

    def test_refuses_when_already_enabled_or_not_installed(self):
        self.state["metrics_ips"] = ["198.51.100.5"]
        with self.assertRaises(InstallerError):
            cli.metrics_command("203.0.113.9", True)
        self.state.pop("metrics_ips")
        self.state["status"] = "repairing"
        with self.assertRaises(InstallerError):
            cli.metrics_command("203.0.113.9", True)

    def test_invalid_ip_changes_nothing(self):
        with mock.patch.object(cli, "repair") as repair:
            with self.assertRaises(InstallerError):
                cli.metrics_command("bogus", True)
        repair.assert_not_called()


if __name__ == "__main__":
    unittest.main()
