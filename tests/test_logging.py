import tempfile
import unittest
from pathlib import Path

from remnawave_node.logging_utils import configure_logger


class LoggingTests(unittest.TestCase):
    def test_secret_never_reaches_log(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "installer.log"
            logger = configure_logger(path, ["secret-value"])
            logger.info("SECRET_KEY=secret-value")
            self.assertNotIn("secret-value", path.read_text(encoding="utf-8"))
            self.assertIn("[REDACTED]", path.read_text(encoding="utf-8"))
            for handler in logger.handlers:
                handler.close()
            logger.handlers.clear()


if __name__ == "__main__":
    unittest.main()
