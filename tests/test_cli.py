import io
import unittest
from unittest.mock import patch

from remnawave_node import cli


class _TtyInput(io.StringIO):
    def isatty(self):
        return True


class InteractiveInputTests(unittest.TestCase):
    def test_plain_input_uses_existing_tty_without_reopening_it(self):
        tty_input = _TtyInput()
        with patch.object(cli.sys, "stdin", tty_input), patch("builtins.input", return_value="node.example.com"):
            self.assertEqual(cli._read_interactive("Домен ноды: "), "node.example.com")

    def test_secret_input_uses_visible_line_input_with_existing_tty(self):
        tty_input = _TtyInput()
        with patch.object(cli.sys, "stdin", tty_input), patch("builtins.input", return_value="node-secret"):
            self.assertEqual(cli._read_interactive("Ключ: ", secret=True), "node-secret")

    def test_tls_mode_defaults_to_xray(self):
        with patch("remnawave_node.cli.tls_mode_from_environment", return_value=None), patch(
            "remnawave_node.cli._read_interactive", return_value=""
        ):
            self.assertEqual(cli._read_tls_mode(), "xray")

    def test_tls_mode_can_select_nginx_websocket_proxy(self):
        with patch("remnawave_node.cli.tls_mode_from_environment", return_value=None), patch(
            "remnawave_node.cli._read_interactive", return_value="2"
        ):
            self.assertEqual(cli._read_tls_mode(), "nginx-ws")

    def test_install_command_accepts_noninteractive_tls_mode(self):
        args = cli._parser().parse_args(["install", "--tls-mode", "nginx-ws", "--ws-proxy-port", "10000"])
        self.assertEqual(args.tls_mode, "nginx-ws")
        self.assertEqual(args.ws_proxy_port, 10000)


if __name__ == "__main__":
    unittest.main()
