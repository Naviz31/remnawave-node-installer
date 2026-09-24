import os
import tempfile
import unittest
from pathlib import Path

from remnawave_node.security import redact, write_private


class SecurityTests(unittest.TestCase):
    def test_redaction(self):
        self.assertNotIn("secret-value", redact("SECRET_KEY=secret-value", ["secret-value"]))
        self.assertIn("[REDACTED]", redact("SECRET_KEY=secret-value", []))

    def test_private_atomic_write(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "private"
            write_private(path, "value\n")
            self.assertEqual(path.read_text(encoding="utf-8"), "value\n")
            if os.name != "nt":
                self.assertEqual(os.stat(path).st_mode & 0o777, 0o600)


if __name__ == "__main__":
    unittest.main()
