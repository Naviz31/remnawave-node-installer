import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from remnawave_node.state import InstallTransaction, StateStore


class StateTests(unittest.TestCase):
    def test_manifest_round_trip_and_secret_absence(self):
        with tempfile.TemporaryDirectory() as directory:
            state_path = Path(directory) / "state.json"
            store = StateStore(state_path)
            with patch("remnawave_node.state.STATE_DIR", Path(directory)), patch("remnawave_node.state.BACKUP_DIR", Path(directory) / "backups"):
                tx = InstallTransaction(store, {})
                tx.begin(domain="node.example.com", node_port=2222, image="remnawave/node:3.4.1", panel_ips=["203.0.113.10"])
                tx.commit()
            loaded = store.load()
            self.assertEqual(loaded["status"], "installed")
            self.assertNotIn("secret-value", json_text(loaded).lower())

    def test_created_path_tracking(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "state.json"
            store = StateStore(path)
            tx = InstallTransaction(store, {})
            with patch("remnawave_node.state.STATE_DIR", Path(directory)), patch("remnawave_node.state.BACKUP_DIR", Path(directory) / "backups"):
                tx.begin(domain="node.example.com", node_port=2222, image="remnawave/node:3.4.1", panel_ips=[])
                tx.record_path(Path(directory) / "managed")
                tx.record_path(Path(directory) / "managed")
            self.assertEqual(list(tx.created_paths()), [Path(directory) / "managed"])


def json_text(value):
    import json
    return json.dumps(value)


if __name__ == "__main__":
    unittest.main()
