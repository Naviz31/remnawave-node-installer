import os
import shutil
from pathlib import Path
from typing import List

from .certificates import certificate_exists, install_renewal_hook, issue_certificate
from .compose import compose, write_node_config
from .constants import (
    APP_NAME,
    COVER_SOCKET,
    INSTALLER_DIR,
    INSTALLER_LOG,
    LOGROTATE_CONFIG,
    NODE_DIR,
    NODE_IMAGE,
    NODE_LOG_DIR,
    NODE_PORT,
)
from .errors import InstallerError
from .firewall import apply_plan, build_iptables_plan, build_nft_plan, build_ufw_plan, detect_backend, find_nft_input_chain, iptables_ipv6_available
from .health import check_health
from .logging_utils import configure_logger
from .nginx import write_nginx_config
from .preflight import run_preflight
from .security import read_env_file
from .ssh_guard import configure_fail2ban, detect_ssh_port
from .state import InstallTransaction
from .system import CommandRunner, installed_packages, is_service_active, package_installed
from .ui import error_box, kv, step, title
from .validators import parse_ips, valid_port
from .website import SITE_ROOT, generate_site


def panel_ips_from_environment() -> List[str]:
    candidates = [os.environ.get("PANEL_IPS", ""), os.environ.get("PANEL_IP", "")]
    config = Path("/etc/remnawave-node/config.env")
    values = dict(read_env_file(config))
    candidates.extend([values.get("PANEL_IPS", ""), values.get("PANEL_IP", "")])
    for candidate in candidates:
        if candidate.strip():
            try:
                return parse_ips(candidate)
            except ValueError as exc:
                raise InstallerError(str(exc), stage="preflight") from exc
    return []


def node_port_from_environment() -> int:
    config = dict(read_env_file(Path("/etc/remnawave-node/config.env")))
    raw = os.environ.get("NODE_PORT", config.get("NODE_PORT", str(NODE_PORT)))
    try:
        value = int(raw)
    except ValueError as exc:
        raise InstallerError("NODE_PORT должен быть числом", stage="preflight") from exc
    if not valid_port(value) or value == 61001:
        raise InstallerError("NODE_PORT должен быть портом 1-65535 и не может быть 61001", stage="preflight")
    return value


def install_packages(runner: CommandRunner, tx: InstallTransaction) -> None:
    packages = ["ca-certificates", "curl", "dnsutils", "fail2ban", "logrotate", "nginx", "certbot", "iproute2", "iptables", "nftables"]
    missing = [name for name in packages if not package_installed(name)]
    if missing:
        tx.data.setdefault("installed_packages", []).extend(name for name in missing if name not in tx.data.get("installed_packages", []))
        tx.state.save(tx.data)
        runner.run(["apt-get", "update"], timeout=600)
        runner.run(["apt-get", "install", "-y", *missing], timeout=900)
        tx.state.save(tx.data)


def ensure_docker(runner: CommandRunner, tx: InstallTransaction) -> None:
    existed = runner.exists("docker") and runner.run(["docker", "info"], check=False, timeout=60).returncode == 0
    tx.mark_preexisting("docker", existed)
    if not runner.exists("docker"):
        before = set(installed_packages())
        tx.data["docker_installed_by_installer"] = True
        tx.state.save(tx.data)
        try:
            runner.run(["sh", "-c", "curl -fsSL https://get.docker.com | sh"], timeout=900)
        finally:
            tx.data["docker_packages"] = sorted(set(installed_packages()) - before)
            tx.state.save(tx.data)
    runner.run(["systemctl", "enable", "--now", "docker"], timeout=60)
    runner.run(["docker", "info"], timeout=60)
    runner.run(["docker", "compose", "version"], timeout=60)


def install_persistent_cli(tx: InstallTransaction) -> None:
    source_root = Path(__file__).resolve().parents[1]
    try:
        same_root = source_root.resolve() == INSTALLER_DIR.resolve()
    except OSError:
        same_root = False
    existed = INSTALLER_DIR.exists()
    tx.mark_preexisting("installer_dir", existed)
    if not same_root:
        if existed:
            raise InstallerError(f"каталог {INSTALLER_DIR} уже существует; проверьте старую установку перед повтором", stage="snapshot")
        tx.record_path(INSTALLER_DIR)
        shutil.copytree(source_root, INSTALLER_DIR, ignore=shutil.ignore_patterns(".git", "__pycache__", ".pytest_cache"))
    wrapper = Path("/usr/local/bin/remnawave-node")
    tx.mark_preexisting("wrapper", wrapper.exists())
    if wrapper.exists():
        tx.backup_file(wrapper)
    else:
        tx.record_path(wrapper)
    wrapper.parent.mkdir(parents=True, exist_ok=True)
    wrapper.write_text("#!/bin/sh\nexport PYTHONPATH=\"/opt/remnawave-node-installer${PYTHONPATH:+:$PYTHONPATH}\"\nexec python3 -m remnawave_node.cli \"$@\"\n", encoding="utf-8")
    wrapper.chmod(0o755)


def write_logrotate(tx: InstallTransaction) -> None:
    existed = LOGROTATE_CONFIG.exists()
    if existed:
        tx.backup_file(LOGROTATE_CONFIG)
    LOGROTATE_CONFIG.parent.mkdir(parents=True, exist_ok=True)
    LOGROTATE_CONFIG.write_text("""/var/log/remnawave-node/*.log /var/log/remnanode/*.log {\n    daily\n    rotate 7\n    compress\n    missingok\n    notifempty\n    copytruncate\n}\n""", encoding="utf-8")
    if not existed:
        tx.record_path(LOGROTATE_CONFIG)
    LOGROTATE_CONFIG.chmod(0o644)


def maybe_fail(stage: str) -> None:
    if os.environ.get("REMNAWAVE_NODE_FAIL_AT", "").strip().lower() == stage.lower():
        raise InstallerError(f"тестовая ошибка на этапе {stage}", stage=stage)


def restore_service_states(runner: CommandRunner, snapshots: dict) -> None:
    """Restore enablement/activity and reload an originally active Nginx."""
    for service, snapshot in snapshots.items():
        if snapshot.get("enabled"):
            runner.run(["systemctl", "enable", service], check=False, timeout=30)
        else:
            runner.run(["systemctl", "disable", service], check=False, timeout=30)
        runner.run(["systemctl", "start" if snapshot.get("active") else "stop", service], check=False, timeout=30)
    nginx = snapshots.get("nginx", {})
    if nginx.get("active"):
        runner.run(["systemctl", "reload", "nginx"], check=False, timeout=30)


def rollback(tx: InstallTransaction, runner: CommandRunner) -> None:
    errors = []
    try:
        if tx.data.get("node_started"):
            compose(runner, NODE_DIR, "down", check=False)
        if tx.data.get("created_firewall"):
            from .firewall import remove_managed_firewall
            remove_managed_firewall(tx.data["created_firewall"], runner, int(tx.data.get("node_port", NODE_PORT)))
        if tx.data.get("certificate_attempted") and not tx.data.get("certificate_preexisting") and tx.data.get("domain"):
            runner.run(["certbot", "delete", "--cert-name", tx.data["domain"], "--non-interactive"], check=False, timeout=120)
        tx.restore_backups()
        for path in sorted(tx.created_paths(), key=lambda value: len(str(value)), reverse=True):
            if path.is_symlink() or path.is_file() or (path.exists() and not path.is_dir()):
                path.unlink(missing_ok=True)
            elif path.is_dir():
                if path in (INSTALLER_DIR, NODE_DIR, SITE_ROOT, NODE_LOG_DIR):
                    shutil.rmtree(path, ignore_errors=True)
                else:
                    try:
                        path.rmdir()
                    except OSError:
                        continue
    except Exception as exc:
        errors.append(str(exc))
    try:
        restore_service_states(runner, tx.data.get("services_before", {}))
        packages = list(dict.fromkeys(tx.data.get("installed_packages", []) + tx.data.get("docker_packages", [])))
        if packages:
            runner.run(["apt-get", "remove", "-y", "--purge", *packages], check=False, timeout=900)
    except Exception as exc:
        errors.append(str(exc))
    if errors:
        tx.data["rollback_error"] = "; ".join(errors)
    tx.mark_rollback()


def install(domain: str, secret: str, *, skip_dns: bool = False) -> int:
    logger = configure_logger(INSTALLER_LOG, [secret])
    runner = CommandRunner(logger, [secret])
    panel_ips = panel_ips_from_environment()
    if not panel_ips:
        raise InstallerError("PANEL_IPS обязателен: укажите IP панели в /etc/remnawave-node/config.env или переменной окружения", stage="preflight")
    node_port = node_port_from_environment()
    tx = InstallTransaction()
    try:
        title(APP_NAME)
        step("Preflight", "running")
        report = run_preflight(domain, runner=runner, skip_dns=skip_dns, node_port=node_port)
        step("Preflight", "ok")
        if report.warnings:
            for warning in report.warnings:
                step(warning, "warn")
        tx.begin(domain=report.domain, node_port=node_port, image=NODE_IMAGE, panel_ips=panel_ips)
        tx.data["services_before"] = {
            name: {"active": is_service_active(runner, name), "enabled": runner.run(["systemctl", "is-enabled", "--quiet", name], check=False, timeout=10).returncode == 0}
            for name in ("docker", "nginx", "fail2ban")
        }
        tx.state.save(tx.data)
        install_persistent_cli(tx)
        for path, key in ((NODE_DIR, "node_dir"), (Path("/etc/nginx"), "nginx"), (Path("/etc/fail2ban"), "fail2ban")):
            tx.mark_preexisting(key, path.exists())

        maybe_fail("dependencies")
        step("Установка системных зависимостей", "running")
        install_packages(runner, tx)
        step("Установка системных зависимостей", "ok")

        maybe_fail("docker")
        step("Docker", "running")
        ensure_docker(runner, tx)
        step("Docker", "ok")

        maybe_fail("node")
        step("Remnawave Node", "running")
        log_dir_existed = NODE_LOG_DIR.exists()
        NODE_LOG_DIR.mkdir(parents=True, exist_ok=True)
        if not log_dir_existed:
            tx.record_path(NODE_LOG_DIR)
        node_dir_existed = NODE_DIR.exists()
        NODE_DIR.mkdir(parents=True, exist_ok=True)
        if not node_dir_existed:
            tx.record_path(NODE_DIR)
        tx.record_path(NODE_DIR / ".env")
        tx.record_path(NODE_DIR / "docker-compose.yml")
        tx.record_path(NODE_DIR / ".image")
        write_node_config(NODE_DIR, node_port=node_port, secret=secret, image=NODE_IMAGE, runner=runner)
        compose(runner, NODE_DIR, "up", "-d")
        tx.data["node_started"] = True
        tx.state.save(tx.data)
        step("Remnawave Node", "ok")

        maybe_fail("firewall")
        step("Firewall", "running")
        backend = detect_backend(runner)
        ssh_port = detect_ssh_port(runner)
        if backend == "ufw":
            plan = build_ufw_plan(panel_ips, ssh_port, node_port)
        elif backend == "nftables":
            input_chain = find_nft_input_chain(runner)
            if not input_chain:
                raise InstallerError("обнаружен nftables без inet input chain; firewall не изменён, настройте правило Node API вручную", stage="firewall")
            plan = build_nft_plan(panel_ips, ssh_port, node_port, input_chain)
        elif backend == "iptables":
            if not iptables_ipv6_available(runner):
                raise InstallerError("для iptables необходимы iptables и ip6tables: IPv6 Node API нельзя безопасно закрыть", stage="firewall")
            plan = build_iptables_plan(panel_ips, ssh_port, node_port)
        else:
            plan = build_nft_plan(panel_ips, ssh_port, node_port)
            plan.warnings.append("активный firewall не найден; создана отдельная nftables-таблица")
        apply_plan(plan, runner, on_created=tx.record_firewall)
        tx.data["firewall_backend"] = plan.backend
        tx.state.save(tx.data)
        for warning in plan.warnings:
            step(warning, "warn")
        step("Firewall", "ok")

        maybe_fail("ssh")
        step("SSH protection", "running")
        if not configure_fail2ban(runner, tx.backup_file, on_created=tx.record_path):
            step("Fail2ban не найден; существующая SSH-конфигурация не изменена", "warn")
        step("SSH protection", "ok")

        maybe_fail("nginx")
        step("Nginx и cover website", "running")
        generate_site(SITE_ROOT, report.domain, on_created=tx.record_path)
        tx.record_path(Path(COVER_SOCKET))
        write_nginx_config(report.domain, certificate=False, runner=runner, backup=tx.backup_file, on_created=tx.record_path)
        step("Nginx и cover website", "ok")

        maybe_fail("tls")
        step("TLS certificate", "running")
        tx.data["certificate_attempted"] = True
        tx.data["certificate_preexisting"] = certificate_exists(report.domain)
        tx.state.save(tx.data)
        cert_created = issue_certificate(report.domain, runner)
        tx.data["certificate_created"] = cert_created
        write_nginx_config(report.domain, certificate=True, runner=runner)
        install_renewal_hook(report.domain, runner, on_created=tx.record_path)
        step("TLS certificate", "ok")

        maybe_fail("logs")
        step("Logs and logrotate", "running")
        write_logrotate(tx)
        step("Logs and logrotate", "ok")

        maybe_fail("health")
        step("Health checks", "running")
        health = check_health(runner, node_port=node_port, domain=report.domain)
        tx.data["health_after_install"] = health
        if health.get("xray") == "listening" and health.get("self_steal") == "ok":
            tx.data["xray_was_active"] = True
        tx.state.save(tx.data)
        if health.get("container") != "running":
            raise InstallerError("контейнер remnanode не подтверждён как running", stage="health", hint="проверьте docker compose logs")
        step("Health checks", "ok")
        tx.commit()

        title("Remnawave Node готов")
        kv("Домен", report.domain)
        kv("Публичный IPv4", report.public_ipv4 or "не определён", "warn" if not report.public_ipv4 else "ok")
        kv("Node API", f":{node_port} / только IP панели")
        kv("Cover backend", "/dev/shm/nginx.sock")
        kv("TLS", "валидирован")
        kv("Remnawave Node", "контейнер запущен")
        if health.get("xray") == "waiting-for-panel-config":
            step("Xray ждёт Config Profile из панели — это нормально до настройки узла", "warn")
        print("\nКоманды: remnawave-node status · doctor · repair · logs")
        return 0
    except KeyboardInterrupt:
        if tx.data:
            rollback(tx, runner)
        error_box("прервано", "получен сигнал остановки", str(INSTALLER_LOG))
        return 130
    except Exception as exc:
        if tx.data:
            rollback(tx, runner)
        stage = getattr(exc, "stage", "preflight")
        message = str(exc)
        if getattr(exc, "hint", ""):
            message += f" ({exc.hint})"
        logger.exception("installation failed at %s: %s", stage, message)
        error_box(stage, message, str(INSTALLER_LOG))
        return 1
