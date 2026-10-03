import unittest

from remnawave_node.metrics import prometheus_report


class PrometheusReportTests(unittest.TestCase):
    def test_contains_all_connection_details(self):
        text = "\n".join(prometheus_report("203.0.113.10", ["198.51.100.5", "2001:db8::1"], True))
        self.assertIn("http://203.0.113.10:9100/metrics", text)
        self.assertIn("198.51.100.5, 2001:db8::1", text)
        self.assertIn('targets: ["203.0.113.10:9100"]', text)
        self.assertIn("job_name: node-exporter", text)
        self.assertIn("curl -s http://203.0.113.10:9100/metrics", text)
        self.assertIn("запущен", text)

    def test_unknown_public_ip_and_stopped_exporter(self):
        text = "\n".join(prometheus_report(None, ["198.51.100.5"], False))
        self.assertIn("IP_НОДЫ:9100", text)
        self.assertIn("остановлен", text)


if __name__ == "__main__":
    unittest.main()
