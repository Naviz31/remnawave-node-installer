import unittest
from unittest.mock import patch

from remnawave_node.errors import InstallerError
from remnawave_node.install import restore_service_states, ws_proxy_port_from_environment


class Recorder:
    def __init__(self):
        self.commands = []

    def run(self, args, **kwargs):
        self.commands.append(args)


class InstallTests(unittest.TestCase):
    def test_restore_service_states_reloads_active_nginx(self):
        runner = Recorder()
        restore_service_states(
            runner,
            {
                "nginx": {"active": True, "enabled": True},
                "docker": {"active": False, "enabled": False},
            },
        )
        self.assertIn(["systemctl", "enable", "nginx"], runner.commands)
        self.assertIn(["systemctl", "stop", "docker"], runner.commands)
        self.assertIn(["systemctl", "reload", "nginx"], runner.commands)

    def test_ws_proxy_port_uses_default(self):
        with patch("remnawave_node.install.read_env_file", return_value=[]), patch.dict("os.environ", {}, clear=True):
            self.assertEqual(ws_proxy_port_from_environment(), 10000)

    def test_ws_proxy_port_rejects_reserved_port(self):
        with patch("remnawave_node.install.read_env_file", return_value=[]), patch.dict("os.environ", {"WS_PROXY_PORT": "443"}, clear=True):
            with self.assertRaises(InstallerError):
                ws_proxy_port_from_environment()

    def test_ws_proxy_port_rejects_internal_reserved_port(self):
        with patch("remnawave_node.install.read_env_file", return_value=[]), patch.dict("os.environ", {"WS_PROXY_PORT": "61001"}, clear=True):
            with self.assertRaises(InstallerError):
                ws_proxy_port_from_environment()

    def test_ws_proxy_port_rejects_node_api_collision(self):
        with patch("remnawave_node.install.read_env_file", return_value=[]), patch.dict("os.environ", {"WS_PROXY_PORT": "2222"}, clear=True):
            with self.assertRaises(InstallerError):
                ws_proxy_port_from_environment(node_port=2222)


if __name__ == "__main__":
    unittest.main()
