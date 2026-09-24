import unittest
from pathlib import Path

from remnawave_node.nginx import nginx_config


class ConfigTests(unittest.TestCase):
    def test_nginx_never_listens_on_external_443(self):
        text = nginx_config("node.example.com", certificate=True)
        self.assertNotIn("listen 443", text)
        self.assertIn("listen unix:/dev/shm/nginx.sock ssl proxy_protocol;", text)
        self.assertNotIn("9443", text)
        self.assertIn("ssl_certificate /etc/letsencrypt/live/node.example.com/fullchain.pem", text)

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
