import unittest

from remnawave_node.health import probe_public_site
from remnawave_node.system import CommandResult


class FakeRunner:
    def __init__(self, result):
        self.result = result

    def run(self, args, **kwargs):
        return self.result


class HealthTests(unittest.TestCase):
    def test_public_site_probe_requires_http_200_and_html(self):
        runner = FakeRunner(CommandResult(0, "<!doctype html><html>ok</html>\n200"))
        self.assertEqual(probe_public_site(runner, "node.example.com"), "ok")

    def test_public_site_probe_rejects_non_html_response(self):
        runner = FakeRunner(CommandResult(0, "backend error\n200"))
        self.assertEqual(probe_public_site(runner, "node.example.com"), "failed")


if __name__ == "__main__":
    unittest.main()
