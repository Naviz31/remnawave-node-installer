import unittest
from unittest.mock import patch

from remnawave_node.validators import domain_points_to, normalize_domain, parse_ips


class ValidatorsTests(unittest.TestCase):
    def test_normalizes_domain(self):
        self.assertEqual(normalize_domain(" Node.Example.COM. "), "node.example.com")

    def test_rejects_url(self):
        with self.assertRaises(ValueError):
            normalize_domain("https://node.example.com")

    def test_parses_unique_ips(self):
        self.assertEqual(parse_ips("203.0.113.10, 203.0.113.10 2001:db8::10"), ["203.0.113.10", "2001:db8::10"])

    def test_dns_match(self):
        with patch("remnawave_node.validators.resolve_domain", return_value=(["203.0.113.10"], [])):
            self.assertEqual(domain_points_to("node.example.com", "203.0.113.10", None), (True, "DNS указывает на сервер"))


if __name__ == "__main__":
    unittest.main()
