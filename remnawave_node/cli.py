import argparse
import getpass
import os
import shutil
import sys
from pathlib import Path
from typing import Dict

from . import __version__
from .compose import compose, read_node_config, write_node_config
from .constants import APP_NAME, COVER_PORT, FAIL2BAN_CONFIG, INSTALLER_DIR, INSTALLER_LOG, NODE_DIR, NODE_IMAGE, NODE_PORT, STATE_FILE
from .errors import InstallerError
from .firewall import apply_plan, build_iptables_plan, build_nft_plan, build_ufw_plan, detect_backend, remove_managed_firewall
from .health import check_health
from .install import install, panel_ips_from_environment
from .logging_utils import configure_logger
from .nginx import write_nginx_config
from .security import read_env_file, write_private
from .state import StateStore
from .system import CommandRunner, port_listeners, read_os_release
from .ssh_guard import detect_ssh_port
from .ui import error_box, kv, step, title
from .validators import normalize_domain
from .website import SITE_ROOT


def _root_check() -> None:
    if hasattr(os, "geteuid") and os.geteuid() != 0:
        raise InstallerError("команда должна выполняться от root")


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="remnawave-node", description="Безопасное управление Remnawave Node")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = parser.add_subparsers(dest="command")
    install_parser = sub.add_parser("install", help="установить и настроить Node")
    install_parser.add_argument("--skip-dns-check", action="store_true", help="пропустить проверку A/AAAA-записей")
    sub.add_parser("status", help="показать сводный статус")
    sub.add_parser("doctor", help="запустить расширенную диагностику")
    sub.add_parser("repair", help="восстановить управляемые конфигурации")
    uninstall = sub.add_parser("uninstall", help="удалить только ресурсы, созданные установщиком")
    uninstall.add_argument("--yes", action="store_true", help="не запрашивать подтверждение")
    sub.add_parser("update", help="обновить образ Node с rollback при ошибке")
    sub.add_parser("set-secret", help="безопасно заменить ключ Node")
    sub.add_parser("logs", help="показать логи контейнера")
    return parser


def _load_state() -> Dict:
    state = StateStore().load()
    if not state or state.get("status") not in {"installed", "in_progress", "rolled_back"}:
        raise InstallerError("установка Remnawave Node не найдена")
    return state


def _existing_install_menu(skip_dns: bool) -> int:
    state = StateStore().load()
    if state.get("status") != "installed":
        return -1
    print("\nУстановка уже найдена.")
    print(f"Домен: {state.get('domain', 'не задан')}")
    print("1. Status\n2. Repair\n3. Reconfigure domain\n4. Reconfigure SECRET_KEY\n5. Uninstall\n6. Exit")
    choice = input("Выберите действие [1-6]: ").strip()
    if choice == "1":
        return show_status()
    if choice == "2":
        return repair()
    if choice == "3":
        print("Для смены домена используйте uninstall, затем запустите install заново: это сохраняет сертификаты и firewall предсказуемыми.")
        return 0
    if choice == "4":
        return set_secret()
    if choice == "5":
        return uninstall(False)
    return 0


def _runner() -> CommandRunner:
    return CommandRunner(configure_logger(INSTALLER_LOG))


def show_status() -> int:
    state = _load_state()
    runner = _runner()
    health = check_health(runner, NODE_DIR, int(state.get("node_port", NODE_PORT)))
    title(APP_NAME)
    kv("Домен", state.get("domain", "не задан"))
    kv("ОС", f"{read_os_release().get('PRETTY_NAME', 'unknown')}")
    kv("Образ", state.get("image", NODE_IMAGE))
    kv("Docker", health.get("container", "unknown"), "ok" if health.get("container") == "running" else "error")
    kv("Nginx", health.get("nginx", "unknown"), "ok" if health.get("nginx") == "valid" else "error")
    kv("Cover", health.get("cover_backend", "unknown"), "ok" if health.get("cover_backend") == "listening" else "warn")
    kv("Node API", health.get("node_port", "unknown"), "ok" if health.get("node_port") == "listening" else "warn")
    kv("Xray", health.get("xray", "unknown"), "ok" if health.get("xray") == "listening" else "warn")
    return 0


def doctor() -> int:
    state = _load_state()
    runner = _runner()
    title("Диагностика Remnawave Node")
    health = check_health(runner, NODE_DIR, int(state.get("node_port", NODE_PORT)))
    checks = {
        "state manifest": STATE_FILE.is_file(),
        "node .env mode 0600": NODE_DIR.joinpath(".env").exists() and oct(NODE_DIR.joinpath(".env").stat().st_mode & 0o777) == "0o600",
        "compose file": NODE_DIR.joinpath("docker-compose.yml").is_file(),
        "container": health.get("container") == "running",
        "nginx config": health.get("nginx") == "valid",
        "cover localhost": health.get("cover_backend") == "listening",
        "node port": health.get("node_port") == "listening",
        "firewall record": bool(state.get("created_firewall")),
    }
    for label, passed in checks.items():
        step(label, "ok" if passed else "warn")
    listeners = port_listeners(runner)
    if COVER_PORT in listeners and any(not value.startswith("127.0.0.1:") for value in listeners[COVER_PORT]):
        step("9443 слушает не только localhost", "error")
        return 1
    return 0 if all(checks.values()) else 1


def repair() -> int:
    _root_check()
    state = _load_state()
    domain = normalize_domain(state["domain"])
    values = read_node_config(NODE_DIR)
    secret = values.get("SECRET_KEY", "")
    if not secret:
        raise InstallerError("SECRET_KEY не найден в закрытом .env; используйте set-secret")
    runner = _runner()
    write_node_config(NODE_DIR, node_port=int(state.get("node_port", NODE_PORT)), secret=secret, image=state.get("image", NODE_IMAGE), runner=runner)
    compose(runner, NODE_DIR, "up", "-d")
    generate_site(SITE_ROOT)
    write_nginx_config(domain, certificate=True, runner=runner)
    panel_ips = panel_ips_from_environment() or state.get("panel_ips", [])
    remove_managed_firewall(state.get("created_firewall", []), runner)
    backend = detect_backend(runner)
    ssh_port = detect_ssh_port(runner)
    if backend == "ufw":
        plan = build_ufw_plan(panel_ips, ssh_port)
    elif backend == "nftables":
        plan = build_nft_plan(panel_ips, ssh_port)
    elif backend == "iptables":
        plan = build_iptables_plan(panel_ips, ssh_port)
    else:
        plan = build_nft_plan(panel_ips, ssh_port)
    state["created_firewall"] = apply_plan(plan, runner)
    state["panel_ips"] = panel_ips
    health = check_health(runner, NODE_DIR, int(state.get("node_port", NODE_PORT)))
    StateStore().save({**state, "health_after_repair": health, "status": "installed"})
    return 0 if health.get("container") == "running" and health.get("nginx") == "valid" else 1


def set_secret() -> int:
    _root_check()
    state = _load_state()
    first = getpass.getpass("Новый ключ ноды из панели Remnawave: ")
    second = getpass.getpass("Повторите ключ: ")
    if not first or first != second:
        raise InstallerError("ключи не совпадают или пусты")
    env_path = NODE_DIR / ".env"
    old = env_path.read_text(encoding="utf-8")
    old_mode = env_path.stat().st_mode & 0o777
    values = dict(read_env_file(env_path))
    values["SECRET_KEY"] = first
    content = "# Managed by Remnawave Node Installer.\n" + "\n".join(f'{key}="{value}"' for key, value in values.items()) + "\n"
    write_private(env_path, content, mode=0o600)
    runner = _runner()
    try:
        compose(runner, NODE_DIR, "up", "-d")
        health = check_health(runner, NODE_DIR, int(state.get("node_port", NODE_PORT)))
        if health.get("container") != "running":
            raise InstallerError("контейнер не запустился после смены ключа")
    except Exception:
        write_private(env_path, old, mode=old_mode)
        compose(runner, NODE_DIR, "up", "-d", check=False)
        raise
    print("Ключ заменён; значение не выводится.")
    return 0


def update() -> int:
    _root_check()
    state = _load_state()
    runner = _runner()
    old_image = state.get("image", NODE_IMAGE)
    step("Загрузка новой версии образа", "running")
    compose(runner, NODE_DIR, "pull")
    try:
        compose(runner, NODE_DIR, "up", "-d")
        health = check_health(runner, NODE_DIR, int(state.get("node_port", NODE_PORT)))
        if health.get("container") != "running":
            raise InstallerError("новый контейнер не подтвердил состояние running")
    except Exception:
        step("Обновление не прошло; возвращаю предыдущий конфиг", "warn")
        compose(runner, NODE_DIR, "down", check=False)
        compose(runner, NODE_DIR, "up", "-d", check=False)
        raise
    StateStore().save({**state, "image": old_image, "last_update": os.times().elapsed})
    step("Обновление", "ok")
    return 0


def uninstall(confirmed: bool) -> int:
    _root_check()
    state = _load_state()
    if not confirmed:
        print("Будут удалены только ресурсы из install-state.json; Docker, Nginx и чужие правила сохранятся.")
        if input("Введите UNINSTALL для продолжения: ").strip() != "UNINSTALL":
            print("Отменено.")
            return 0
    runner = _runner()
    compose(runner, NODE_DIR, "down", check=False)
    remove_managed_firewall(state.get("created_firewall", []), runner)
    for path in [Path("/etc/nginx/sites-enabled/remnawave-node.conf"), Path("/etc/nginx/sites-available/remnawave-node.conf"), FAIL2BAN_CONFIG, Path("/etc/logrotate.d/remnawave-node")]:
        if path.is_symlink() or path.is_file():
            path.unlink(missing_ok=True)
    wrapper = Path("/usr/local/bin/remnawave-node")
    if not state.get("preexisting", {}).get("wrapper", False):
        wrapper.unlink(missing_ok=True)
    if SITE_ROOT.exists():
        shutil.rmtree(SITE_ROOT)
    for path in [NODE_DIR / ".env", NODE_DIR / "docker-compose.yml", NODE_DIR / ".image"]:
        path.unlink(missing_ok=True)
    try:
        NODE_DIR.rmdir()
    except OSError:
        _ = None
    if not state.get("preexisting", {}).get("installer_dir", False) and INSTALLER_DIR.exists():
        shutil.rmtree(INSTALLER_DIR)
    StateStore().remove()
    print("Удалены только управляемые ресурсы. Docker, пакеты и пользовательские конфигурации сохранены.")
    return 0


def logs() -> int:
    _root_check()
    state = _load_state()
    runner = _runner()
    result = compose(runner, NODE_DIR, "logs", "--tail=200", "-f", check=False)
    print(result.stdout, end="")
    return result.returncode


def main(argv=None) -> int:
    parser = _parser()
    args = parser.parse_args(argv)
    command = args.command or "install"
    try:
        if command == "install":
            _root_check()
            if StateStore().exists():
                existing_result = _existing_install_menu(getattr(args, "skip_dns_check", False))
                if existing_result >= 0:
                    return existing_result
            domain = input("Домен ноды: ").strip()
            normalize_domain(domain)
            secret = getpass.getpass("Ключ ноды из панели Remnawave: ")
            if not secret:
                raise InstallerError("ключ не может быть пустым")
            return install(domain, secret, skip_dns=getattr(args, "skip_dns_check", False))
        if command == "status":
            return show_status()
        if command == "doctor":
            _root_check()
            return doctor()
        if command == "repair":
            return repair()
        if command == "uninstall":
            return uninstall(args.yes)
        if command == "update":
            return update()
        if command == "set-secret":
            return set_secret()
        if command == "logs":
            return logs()
        parser.error(f"неизвестная команда: {command}")
    except InstallerError as exc:
        error_box(getattr(exc, "stage", "general"), str(exc), str(INSTALLER_LOG), rolled_back=False)
        return 1
    except KeyboardInterrupt:
        print("\nОстановлено пользователем.")
        return 130


if __name__ == "__main__":
    sys.exit(main())
