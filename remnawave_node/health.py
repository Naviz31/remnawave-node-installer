import stat
from pathlib import Path
from typing import Dict, Optional

from .compose import compose
from .constants import COVER_SOCKET, NODE_CONTAINER, NODE_DIR, NODE_PORT
from .system import CommandRunner, port_listeners


def socket_exists(path: Path = Path(COVER_SOCKET)) -> bool:
    try:
        return path.exists() and stat.S_ISSOCK(path.stat().st_mode)
    except OSError:
        return False


def probe_public_site(runner: CommandRunner, domain: str) -> str:
    result = runner.run([
        "curl", "-fsS", "--noproxy", "*", "--max-time", "10",
        "-w", "\n%{http_code}", f"https://{domain}/",
    ], check=False, timeout=15)
    if result.returncode != 0:
        return "failed"
    lines = result.stdout.splitlines()
    status = lines[-1].strip() if lines else ""
    body = "\n".join(lines[:-1]).lower()
    return "ok" if status == "200" and "<html" in body else "failed"


def check_health(
    runner: CommandRunner,
    node_dir: Path = NODE_DIR,
    node_port: int = NODE_PORT,
    domain: Optional[str] = None,
) -> Dict[str, str]:
    result: Dict[str, str] = {}
    ps = compose(runner, node_dir, "ps", "--format", "json", check=False)
    result["container"] = "running" if ps.returncode == 0 and NODE_CONTAINER in ps.stdout and "running" in ps.stdout.lower() else "unknown"
    listeners = port_listeners(runner)
    result["node_port"] = "listening" if node_port in listeners else "not-listening"
    result["cover_backend"] = "listening" if socket_exists() else "not-listening"
    result["xray"] = "waiting-for-panel-config" if 443 not in listeners else "listening"
    result["self_steal"] = probe_public_site(runner, domain) if domain and result["xray"] == "listening" else "not-checked"
    nginx = runner.run(["nginx", "-t"], check=False, timeout=30)
    result["nginx"] = "valid" if nginx.returncode == 0 else "invalid"
    return result
