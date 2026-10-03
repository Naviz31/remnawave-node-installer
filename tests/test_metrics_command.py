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
        command.assert_called_once_with("203.0.113.9")


if __name__ == "__main__":
    unittest.main()
