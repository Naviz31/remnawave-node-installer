import unittest

from remnawave_node.errors import InstallerError
from remnawave_node.health import probe_public_site, require_install_health
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

    def test_final_health_requires_node_port(self):
        health = {"container": "running", "node_port": "not-listening", "nginx": "valid", "cover_backend": "listening", "xray": "waiting-for-panel-config"}
        with self.assertRaises(InstallerError):
            require_install_health(health)

    def test_final_health_requires_self_steal_after_xray_activation(self):
        health = {"container": "running", "node_port": "listening", "nginx": "valid", "cover_backend": "listening", "xray": "not-listening", "self_steal": "not-checked"}
        with self.assertRaises(InstallerError):
            require_install_health(health, xray_was_active=True)


if __name__ == "__main__":
    unittest.main()
