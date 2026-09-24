import sys
import unittest

from remnawave_node.cli import latest_node_image
from remnawave_node.system import CommandResult, CommandRunner


class SystemTests(unittest.TestCase):
    def test_stream_returns_process_code_without_capture_mode(self):
        self.assertEqual(CommandRunner().stream([sys.executable, "-c", "pass"]), 0)

    def test_latest_image_uses_highest_stable_semver_tag(self):
        class FakeRunner:
            def run(self, args, **kwargs):
                return CommandResult(0, '{"results":[{"name":"3.4.1"},{"name":"3.4.2"},{"name":"3.5.0-rc1"},{"name":"4.0.0"},{"name":"latest"}]}')

        self.assertEqual(latest_node_image(FakeRunner(), "remnawave/node:3.4.1"), "remnawave/node:3.4.2")


if __name__ == "__main__":
    unittest.main()
