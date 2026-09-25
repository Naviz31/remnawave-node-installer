import unittest
from pathlib import Path

from remnawave_node.nginx import nginx_config


class ConfigTests(unittest.TestCase):
    def test_xray_mode_leaves_external_443_to_xray(self):
        text = nginx_config("node.example.com", certificate=True)
        self.assertNotIn("listen 443", text)
        self.assertIn("listen unix:/dev/shm/nginx.sock ssl proxy_protocol;", text)
        self.assertNotIn("9443", text)
        self.assertIn("ssl_certificate /etc/letsencrypt/live/node.example.com/fullchain.pem", text)

    def test_nginx_ws_mode_terminates_tls_and_forwards_websockets_without_a_fixed_path(self):
        text = nginx_config("node.example.com", certificate=True, tls_mode="nginx-ws", ws_proxy_port=10000)
        self.assertIn("listen 443 ssl;", text)
        self.assertIn("proxy_pass http://127.0.0.1:10000;", text)
        self.assertIn("proxy_set_header Upgrade $http_upgrade;", text)
        self.assertIn("proxy_set_header Connection upgrade;", text)
        self.assertIn("location @cover", text)
        self.assertNotIn("api/v1/status", text)

    def test_nginx_ws_mode_does_not_enable_tls_listener_before_certificate(self):
        text = nginx_config("node.example.com", certificate=False, tls_mode="nginx-ws")
        self.assertNotIn("listen 443", text)

    def test_cover_text_is_neutral(self):
        forbidden = ("Remnawave", "VLESS", "Reality", "VPN", "Proxy", "Tunnel")
        site_file = Path(__file__).parents[1] / "remnawave_node" / "website.py"
        text = site_file.read_text(encoding="utf-8")
        for word in forbidden:
            self.assertNotIn(word, text)

    def test_site_identity_changes_generated_brand(self):
        from tempfile import TemporaryDirectory

        from remnawave_node.website import generate_site

        with TemporaryDirectory() as first, TemporaryDirectory() as second:
            generate_site(Path(first), "node-one.example.com")
            generate_site(Path(second), "node-two.example.com")
            first_text = (Path(first) / "index.html").read_text(encoding="utf-8")
            second_text = (Path(second) / "index.html").read_text(encoding="utf-8")
            self.assertNotEqual(first_text, second_text)
            self.assertNotEqual(
                (Path(first) / "assets" / "site.css").read_text(encoding="utf-8"),
                (Path(second) / "assets" / "site.css").read_text(encoding="utf-8"),
            )


if __name__ == "__main__":
    unittest.main()
