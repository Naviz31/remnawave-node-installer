import unittest
from pathlib import Path

from remnawave_node.nginx import nginx_config


class ConfigTests(unittest.TestCase):
    def test_nginx_never_listens_on_external_443(self):
        text = nginx_config("node.example.com", certificate=True)
        self.assertNotIn("listen 443", text)
        self.assertIn("listen 127.0.0.1:9443 ssl", text)
        self.assertIn("listen 127.0.0.1:9443 ssl;", text)
        self.assertIn("ssl_certificate /etc/letsencrypt/live/node.example.com/fullchain.pem", text)

    def test_cover_text_is_neutral(self):
        forbidden = ("Remnawave", "VLESS", "Reality", "VPN", "Proxy", "Tunnel")
        site_file = Path(__file__).parents[1] / "remnawave_node" / "website.py"
        text = site_file.read_text(encoding="utf-8")
        for word in forbidden:
            self.assertNotIn(word, text)


if __name__ == "__main__":
    unittest.main()
