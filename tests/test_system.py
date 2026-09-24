import unittest

from remnawave_node.system import CommandResult, established_peers


class FakeRunner:
    def run(self, args, **kwargs):
        return CommandResult(0, "ESTAB 0 0 10.0.0.2:2222 203.0.113.10:49152\nESTAB 0 0 127.0.0.1:2222 127.0.0.1:50000\n")


class SystemTests(unittest.TestCase):
    def test_reads_only_external_peers_on_node_port(self):
        self.assertEqual(established_peers(FakeRunner(), 2222), ["203.0.113.10"])


if __name__ == "__main__":
    unittest.main()
