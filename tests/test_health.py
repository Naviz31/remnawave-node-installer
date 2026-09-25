import unittest
from unittest.mock import patch

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

    def test_nginx_ws_install_requires_tls_ingress_and_cover(self):
        health = {
            "container": "running",
            "node_port": "listening",
            "nginx": "valid",
            "cover_backend": "listening",
            "tls_ingress": "listening",
            "public_https": "ok",
            "ws_backend": "waiting-for-panel-config",
        }
        require_install_health(health, tls_mode="nginx-ws")

    def test_nginx_ws_health_fails_if_an_active_backend_disappears(self):
        health = {
            "container": "running",
            "node_port": "listening",
            "nginx": "valid",
            "cover_backend": "listening",
            "tls_ingress": "listening",
            "public_https": "ok",
            "ws_backend": "waiting-for-panel-config",
        }
        with self.assertRaises(InstallerError):
            require_install_health(health, tls_mode="nginx-ws", ws_backend_was_active=True)

    def test_nginx_ws_health_distinguishes_tls_listener_from_xray_backend(self):
        runner = FakeRunner(CommandResult(0, '{"Name":"remnanode","State":"running"}'))
        with patch("remnawave_node.health.port_listeners", return_value={2222: [], 443: [], 10000: ["127.0.0.1:10000"]}), patch(
            "remnawave_node.health.socket_exists", return_value=True
        ), patch("remnawave_node.health.probe_public_site", return_value="ok"):
            from remnawave_node.health import check_health

            health = check_health(runner, domain="node.example.com", tls_mode="nginx-ws", ws_proxy_port=10000)
        self.assertEqual(health["tls_ingress"], "listening")
        self.assertEqual(health["ws_backend"], "listening")
        self.assertEqual(health["xray"], "behind-nginx")
        self.assertEqual(health["public_https"], "ok")

    def test_nginx_ws_backend_must_not_listen_on_public_interfaces(self):
        health = {
            "container": "running",
            "node_port": "listening",
            "nginx": "valid",
            "cover_backend": "listening",
            "tls_ingress": "listening",
            "public_https": "ok",
            "ws_backend": "exposed",
        }
        with self.assertRaises(InstallerError):
            require_install_health(health, tls_mode="nginx-ws")


if __name__ == "__main__":
    unittest.main()
