import unittest

from remnawave_node.install import restore_service_states


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


if __name__ == "__main__":
    unittest.main()
