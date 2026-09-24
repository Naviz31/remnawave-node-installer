import sys
import unittest

from remnawave_node.system import CommandRunner


class SystemTests(unittest.TestCase):
    def test_stream_returns_process_code_without_capture_mode(self):
        self.assertEqual(CommandRunner().stream([sys.executable, "-c", "pass"]), 0)


if __name__ == "__main__":
    unittest.main()
