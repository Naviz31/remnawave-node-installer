import socket
import sys
import tempfile
import unittest
from pathlib import Path

from remnawave_node.health import socket_exists


@unittest.skipUnless(sys.platform.startswith("linux"), "Linux smoke test")
class LinuxSmokeTests(unittest.TestCase):
    def test_real_unix_socket_is_detected(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "nginx.sock"
            server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            try:
                server.bind(str(path))
                self.assertTrue(socket_exists(path))
            finally:
                server.close()


if __name__ == "__main__":
    unittest.main()
