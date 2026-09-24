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

    def test_secret_input_uses_getpass_with_existing_tty(self):
        tty_input = _TtyInput()
        with patch.object(cli.sys, "stdin", tty_input), patch.object(cli.getpass, "getpass", return_value="node-secret"):
            self.assertEqual(cli._read_interactive("Ключ: ", secret=True), "node-secret")


if __name__ == "__main__":
    unittest.main()
