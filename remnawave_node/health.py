import ipaddress
import stat
from pathlib import Path
from typing import Dict, Optional

from .compose import compose
from .constants import COVER_SOCKET, DEFAULT_TLS_MODE, DEFAULT_WS_PROXY_PORT, NODE_CONTAINER, NODE_DIR, NODE_PORT, TLS_MODE_NGINX_WS
from .errors import InstallerError
from .system import CommandRunner, port_listeners


def _listener_is_loopback(address: str) -> bool:
    host = address.rsplit(":", 1)[0]
    if host.startswith("[") and host.endswith("]"):
        host = host[1:-1]
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


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
    tls_mode: str = DEFAULT_TLS_MODE,
    ws_proxy_port: int = DEFAULT_WS_PROXY_PORT,
) -> Dict[str, str]:
    result: Dict[str, str] = {}
    ps = compose(runner, node_dir, "ps", "--format", "json", check=False)
    result["container"] = "running" if ps.returncode == 0 and NODE_CONTAINER in ps.stdout and "running" in ps.stdout.lower() else "unknown"
    listeners = port_listeners(runner)
    result["node_port"] = "listening" if node_port in listeners else "not-listening"
    result["cover_backend"] = "listening" if socket_exists() else "not-listening"
    result["tls_ingress"] = "listening" if 443 in listeners else "not-listening"
    if tls_mode == TLS_MODE_NGINX_WS:
        ws_addresses = listeners.get(ws_proxy_port, [])
        if not ws_addresses:
            result["ws_backend"] = "waiting-for-panel-config"
        elif all(_listener_is_loopback(address) for address in ws_addresses):
            result["ws_backend"] = "listening"
        else:
            result["ws_backend"] = "exposed"
        result["xray"] = "behind-nginx" if result["ws_backend"] == "listening" else result["ws_backend"]
        result["self_steal"] = "not-applicable"
        result["public_https"] = probe_public_site(runner, domain) if domain and result["tls_ingress"] == "listening" else "not-checked"
    else:
        result["xray"] = "waiting-for-panel-config" if 443 not in listeners else "listening"
        result["self_steal"] = probe_public_site(runner, domain) if domain and result["xray"] == "listening" else "not-checked"
        result["public_https"] = result["self_steal"]
    nginx = runner.run(["nginx", "-t"], check=False, timeout=30)
    result["nginx"] = "valid" if nginx.returncode == 0 else "invalid"
    return result


def require_install_health(
    health: Dict[str, str],
    *,
    xray_was_active: bool = False,
    tls_mode: str = DEFAULT_TLS_MODE,
    ws_backend_was_active: bool = False,
) -> None:
    """Reject a successful install/update when its required runtime path is not healthy."""
    required = {
        "container": "running",
        "node_port": "listening",
        "nginx": "valid",
        "cover_backend": "listening",
    }
    if tls_mode == TLS_MODE_NGINX_WS:
        required.update({"tls_ingress": "listening", "public_https": "ok"})
        if ws_backend_was_active or health.get("ws_backend") == "exposed":
            required["ws_backend"] = "listening"
    elif xray_was_active or health.get("xray") == "listening":
        required.update({"xray": "listening", "self_steal": "ok"})
    missing = [name for name, expected in required.items() if health.get(name) != expected]
    if missing:
        raise InstallerError(f"финальная health-проверка не пройдена: {', '.join(missing)}", stage="health")
