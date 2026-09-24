import os
import platform
import shutil
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional

from .constants import COVER_SOCKET, FAIL2BAN_CONFIG, LOGROTATE_CONFIG, NGINX_AVAILABLE, NGINX_ENABLED, NODE_DIR, NODE_PORT, RENEWAL_HOOK, SUPPORTED_OS
from .errors import PreflightError
from .system import CommandRunner, memory_bytes, port_listeners, public_ip, read_os_release
from .validators import domain_points_to, normalize_domain
from .website import SITE_ROOT


@dataclass
class PreflightReport:
    domain: str
    public_ipv4: Optional[str] = None
    public_ipv6: Optional[str] = None
    os_name: str = "unknown"
    os_version: str = "unknown"
    warnings: List[str] = field(default_factory=list)
    checks: List[tuple] = field(default_factory=list)


def run_preflight(domain: str, *, runner: CommandRunner, skip_dns: bool = False, node_port: int = NODE_PORT) -> PreflightReport:
    domain = normalize_domain(domain)
    report = PreflightReport(domain=domain)
    if hasattr(os, "geteuid") and os.geteuid() != 0:
        raise PreflightError("запустите установщик от root", stage="preflight")
    os_data = read_os_release()
    report.os_name = os_data.get("ID", "unknown")
    report.os_version = os_data.get("VERSION_ID", "unknown")
    if report.os_name not in SUPPORTED_OS or report.os_version not in SUPPORTED_OS[report.os_name]:
        raise PreflightError(f"ОС {report.os_name} {report.os_version} не поддерживается; нужны Ubuntu 22.04/24.04 или Debian 12/13", stage="preflight")
    if not Path("/run/systemd/system").exists() and not runner.exists("systemctl"):
        raise PreflightError("systemd не найден", stage="preflight")
    if platform.machine().lower() not in {"x86_64", "amd64", "aarch64", "arm64"}:
        raise PreflightError(f"архитектура {platform.machine()} не поддерживается", stage="preflight")
    if memory_bytes() and memory_bytes() < 1024 * 1024 * 1024:
        raise PreflightError("нужно минимум 1 ГБ RAM", stage="preflight")
    usage = shutil.disk_usage("/")
    if usage.free < 5 * 1024 * 1024 * 1024:
        raise PreflightError("нужно минимум 5 ГБ свободного места", stage="preflight")
    if not runner.exists("curl"):
        raise PreflightError("не найден curl; установите его или запустите bootstrap install.sh", stage="preflight")
    network = runner.run(["curl", "-fsS", "--max-time", "8", "https://1.1.1.1/cdn-cgi/trace"], check=False, timeout=12)
    if network.returncode != 0:
        raise PreflightError("нет исходящего доступа в интернет", stage="preflight")
    report.public_ipv4 = public_ip(runner, 4)
    report.public_ipv6 = public_ip(runner, 6)
    if not skip_dns:
        ok, message = domain_points_to(domain, report.public_ipv4, report.public_ipv6)
        if not ok:
            expected = report.public_ipv4 or "публичный IP"
            raise PreflightError(f"DNS-проверка не пройдена: {message}; ожидается {expected}. Используйте --skip-dns-check только осознанно", stage="preflight")
        report.checks.append(("DNS", "ok"))
    else:
        report.warnings.append("DNS-проверка пропущена по флагу")
    listeners = port_listeners(runner)
    for port in (80, 443):
        if port in listeners:
            raise PreflightError(f"порт {port} уже занят ({', '.join(listeners[port])}); установка остановлена до изменений", stage="preflight")
    for managed_path in (NODE_DIR / ".env", NODE_DIR / "docker-compose.yml", NGINX_AVAILABLE, NGINX_ENABLED, FAIL2BAN_CONFIG, LOGROTATE_CONFIG, RENEWAL_HOOK, SITE_ROOT, Path(COVER_SOCKET)):
        if managed_path.exists():
            raise PreflightError(f"управляемый путь уже существует: {managed_path}; используйте status/repair или сначала завершите старую установку", stage="preflight")
    if node_port in listeners:
        raise PreflightError(f"порт Node API {node_port} уже занят ({', '.join(listeners[node_port])}); установка остановлена до изменений", stage="preflight")
    report.checks.extend([
        ("root", "ok"),
        ("supported OS", "ok"),
        ("systemd", "ok"),
        ("resources", "ok"),
        ("network", "ok"),
        ("ports", "checked"),
    ])
    return report
