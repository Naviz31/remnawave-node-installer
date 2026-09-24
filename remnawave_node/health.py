from pathlib import Path
from typing import Dict

from .compose import compose
from .constants import COVER_PORT, NODE_CONTAINER, NODE_DIR, NODE_PORT
from .system import CommandRunner, port_listeners


def check_health(runner: CommandRunner, node_dir: Path = NODE_DIR, node_port: int = NODE_PORT) -> Dict[str, str]:
    result: Dict[str, str] = {}
    ps = compose(runner, node_dir, "ps", "--format", "json", check=False)
    result["container"] = "running" if ps.returncode == 0 and NODE_CONTAINER in ps.stdout and "running" in ps.stdout.lower() else "unknown"
    listeners = port_listeners(runner)
    result["node_port"] = "listening" if node_port in listeners else "not-listening"
    result["cover_backend"] = "listening" if COVER_PORT in listeners and any(value.startswith("127.0.0.1:") for value in listeners[COVER_PORT]) else "not-listening"
    result["xray"] = "waiting-for-panel-config" if 443 not in listeners else "listening"
    nginx = runner.run(["nginx", "-t"], check=False, timeout=30)
    result["nginx"] = "valid" if nginx.returncode == 0 else "invalid"
    return result
