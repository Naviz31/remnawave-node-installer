from pathlib import Path
from typing import List, Optional

from .constants import METRICS_PORT, NODE_EXPORTER_CONFIG
from .errors import InstallerError
from .system import CommandRunner
from .ui import title


def configure_node_exporter(runner: CommandRunner) -> None:
    """Enable host metrics on the standard port; firewall rules restrict its source."""
    NODE_EXPORTER_CONFIG.parent.mkdir(parents=True, exist_ok=True)
    NODE_EXPORTER_CONFIG.write_text(
        f'# Managed by the installer. Scrape access is restricted by the host firewall.\nARGS="--web.listen-address=:{METRICS_PORT}"\n',
        encoding="utf-8",
    )
    NODE_EXPORTER_CONFIG.chmod(0o644)
    runner.run(["systemctl", "enable", "--now", "prometheus-node-exporter"], timeout=60)
    runner.run(["systemctl", "restart", "prometheus-node-exporter"], timeout=60)
    active = runner.run(["systemctl", "is-active", "--quiet", "prometheus-node-exporter"], check=False, timeout=10)
    if active.returncode != 0:
        raise InstallerError("экспортёр системных метрик не запустился", stage="metrics")


PROMETHEUS_JOB = "node-exporter"


def prometheus_report(public_ip: Optional[str], allowed_ips: List[str], exporter_active: Optional[bool] = None) -> List[str]:
    """Plain-text block with everything needed to connect this node to Prometheus."""
    host = public_ip or "IP_НОДЫ"
    target = f"{host}:{METRICS_PORT}"
    lines = [
        f"Экспортёр:      {'запущен' if exporter_active else 'остановлен' if exporter_active is False else 'prometheus-node-exporter'}",
        f"Адрес метрик:   http://{target}/metrics",
        f"Забирать метрики: {', '.join(allowed_ips)}  (остальным порт {METRICS_PORT} закрыт файрволом)",
        "",
        "1) На сервере Prometheus добавьте в prometheus.yml (scrape_configs) и перезагрузите его:",
        f"     - job_name: {PROMETHEUS_JOB}",
        "       static_configs:",
        f"         - targets: [\"{target}\"]",
        "",
        "2) Проверка с сервера Prometheus (должны прийти строки с метриками):",
        f"     curl -s http://{target}/metrics | head -n 3",
        "",
        f"3) В Node Control в карточке ноды: IP {host}, порт метрик {METRICS_PORT};",
        f"   в .env панели PROMETHEUS_JOB={PROMETHEUS_JOB}.",
        "",
        "Метрики передаются по HTTP без ключа и шифрования — защита только файрвол,",
        "поэтому указывайте адрес сервера Prometheus точно. Если он изменится, обновите правило для порта 9100.",
    ]
    return lines


def print_prometheus_report(public_ip: Optional[str], allowed_ips: List[str], exporter_active: Optional[bool] = None) -> None:
    title("Prometheus — подключение метрик")
    for line in prometheus_report(public_ip, allowed_ips, exporter_active):
        print(f"  {line}" if line else "")
