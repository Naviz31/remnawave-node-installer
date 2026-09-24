import argparse
import getpass
import json
import os
import re
import shutil
import sys
import time
from pathlib import Path
from typing import Dict

from . import __version__
from .compose import compose, read_node_config, write_node_config
from .constants import APP_NAME, INSTALLER_DIR, INSTALLER_LOG, NODE_DIR, NODE_IMAGE, NODE_LOG_DIR, NODE_PORT, STATE_FILE
from .errors import InstallerError
from .firewall import apply_plan, build_iptables_plan, build_nft_plan, build_ufw_plan, detect_backend, find_nft_input_chain, remove_managed_firewall
from .health import check_health
from .install import install, panel_ips_from_environment
from .logging_utils import configure_logger
from .nginx import write_nginx_config
from .security import env_line, read_env_file, write_private
from .state import StateStore
from .system import CommandRunner, read_os_release
from .ssh_guard import detect_ssh_port
from .ui import error_box, kv, step, title
from .validators import normalize_domain
from .website import SITE_ROOT, generate_site


def _root_check() -> None:
    if hasattr(os, "geteuid") and os.geteuid() != 0:
        raise InstallerError("команда должна выполняться от root")


def _read_interactive(prompt: str, *, secret: bool = False) -> str:
    tty_path = Path("/dev/tty")
    if tty_path.exists():
        with tty_path.open("r+") as tty:
            if secret:
                return getpass.getpass(prompt, stream=tty)
            tty.write(prompt)
            tty.flush()
            return tty.readline().strip()
    return getpass.getpass(prompt) if secret else input(prompt).strip()


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


def latest_node_image(runner: CommandRunner, current_image: str) -> str:
    repository = current_image.rsplit(":", 1)[0] if ":" in current_image.rsplit("/", 1)[-1] else current_image
    endpoint = f"https://hub.docker.com/v2/repositories/{repository}/tags?page_size=100&ordering=last_updated"
    result = runner.run(["curl", "-fsS", "--max-time", "20", endpoint], check=False, timeout=30)
    if result.returncode != 0:
        raise InstallerError("не удалось получить список версий remnawave/node с Docker Hub", stage="update")
    try:
        tags = [item["name"] for item in json.loads(result.stdout).get("results", [])]
    except (KeyError, TypeError, ValueError) as exc:
        raise InstallerError("Docker Hub вернул некорректный список версий Node", stage="update") from exc
    versions = []
    for tag in tags:
        match = re.fullmatch(r"(\d+)\.(\d+)\.(\d+)", tag)
        if match:
            versions.append((tuple(int(part) for part in match.groups()), tag))
    if not versions:
        raise InstallerError("на Docker Hub не найдены стабильные semver-теги Node", stage="update")
    return f"{repository}:{max(versions)[1]}"


def show_status() -> int:
    state = _load_state()
    runner = _runner()
    health = check_health(runner, NODE_DIR, int(state.get("node_port", NODE_PORT)), state.get("domain"))
    title(APP_NAME)
    kv("Домен", state.get("domain", "не задан"))
    kv("ОС", f"{read_os_release().get('PRETTY_NAME', 'unknown')}")
    kv("Образ", state.get("image", NODE_IMAGE))
    kv("Docker", health.get("container", "unknown"), "ok" if health.get("container") == "running" else "error")
    kv("Nginx", health.get("nginx", "unknown"), "ok" if health.get("nginx") == "valid" else "error")
    kv("Cover", health.get("cover_backend", "unknown"), "ok" if health.get("cover_backend") == "listening" else "warn")
    kv("Node API", health.get("node_port", "unknown"), "ok" if health.get("node_port") == "listening" else "warn")
    kv("Self-Steal", health.get("self_steal", "unknown"), "ok" if health.get("self_steal") in {"ok", "not-checked"} else "error")
    kv("Xray", health.get("xray", "unknown"), "ok" if health.get("xray") == "listening" else "warn")
    return 0


def doctor() -> int:
    state = _load_state()
    runner = _runner()
    title("Диагностика Remnawave Node")
    health = check_health(runner, NODE_DIR, int(state.get("node_port", NODE_PORT)), state.get("domain"))
    checks = {
        "state manifest": STATE_FILE.is_file(),
        "node .env mode 0600": NODE_DIR.joinpath(".env").exists() and oct(NODE_DIR.joinpath(".env").stat().st_mode & 0o777) == "0o600",
        "compose file": NODE_DIR.joinpath("docker-compose.yml").is_file(),
        "container": health.get("container") == "running",
        "nginx config": health.get("nginx") == "valid",
        "cover unix socket": health.get("cover_backend") == "listening",
        "node port": health.get("node_port") == "listening",
        "self-steal HTTPS": health.get("self_steal") in {"ok", "not-checked"},
        "firewall record": bool(state.get("created_firewall")),
    }
    for label, passed in checks.items():
        step(label, "ok" if passed else "warn")
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
    generate_site(SITE_ROOT, domain)
    write_nginx_config(domain, certificate=True, runner=runner)
    panel_ips = panel_ips_from_environment() or state.get("panel_ips", [])
    if not panel_ips:
        raise InstallerError("PANEL_IPS обязателен для repair: задайте IP панели в /etc/remnawave-node/config.env")
    node_port = int(state.get("node_port", NODE_PORT))
    remove_managed_firewall(state.get("created_firewall", []), runner, int(state.get("node_port", NODE_PORT)))
    backend = detect_backend(runner)
    ssh_port = detect_ssh_port(runner)
    if backend == "ufw":
        plan = build_ufw_plan(panel_ips, ssh_port, node_port)
    elif backend == "nftables":
        input_chain = find_nft_input_chain(runner)
        if not input_chain:
            raise InstallerError("обнаружен nftables без inet input chain; firewall не изменён")
        plan = build_nft_plan(panel_ips, ssh_port, node_port, input_chain)
    elif backend == "iptables":
        plan = build_iptables_plan(panel_ips, ssh_port, node_port)
    else:
        plan = build_nft_plan(panel_ips, ssh_port, node_port)
    state["created_firewall"] = apply_plan(plan, runner)
    state["panel_ips"] = panel_ips
    health = check_health(runner, NODE_DIR, int(state.get("node_port", NODE_PORT)), state.get("domain"))
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
    content = "# Managed by Remnawave Node Installer.\n" + "\n".join(env_line(key, value) for key, value in values.items()) + "\n"
    write_private(env_path, content, mode=0o600)
    runner = _runner()
    try:
        compose(runner, NODE_DIR, "up", "-d")
        health = check_health(runner, NODE_DIR, int(state.get("node_port", NODE_PORT)), state.get("domain"))
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
    values = read_node_config(NODE_DIR)
    secret = values.get("SECRET_KEY", "")
    if not secret:
        raise InstallerError("SECRET_KEY не найден в закрытом .env; используйте set-secret")
    target_image = latest_node_image(runner, old_image)
    old_id_result = runner.run(["docker", "image", "inspect", old_image, "--format", "{{.Id}}"], check=False, timeout=60)
    old_id = old_id_result.stdout.strip() if old_id_result.returncode == 0 else ""
    repository = old_image.rsplit(":", 1)[0] if ":" in old_image.rsplit("/", 1)[-1] else old_image
    backup_tag = f"{repository}:installer-rollback-{int(time.time())}"
    rollback_tagged = bool(old_id) and runner.run(["docker", "tag", old_image, backup_tag], check=False, timeout=60).returncode == 0
    try:
        step(f"Загрузка версии {target_image.rsplit(':', 1)[-1]}", "running")
        write_node_config(NODE_DIR, node_port=int(state.get("node_port", NODE_PORT)), secret=secret, image=target_image, runner=runner)
        compose(runner, NODE_DIR, "pull")
        compose(runner, NODE_DIR, "up", "-d")
        health = check_health(runner, NODE_DIR, int(state.get("node_port", NODE_PORT)), state.get("domain"))
        if health.get("container") != "running" or health.get("self_steal") == "failed":
            raise InstallerError("новый контейнер не подтвердил running и Self-Steal health check")
    except Exception:
        step("Обновление не прошло; возвращаю предыдущий образ", "warn")
        compose(runner, NODE_DIR, "down", check=False)
        if rollback_tagged:
            runner.run(["docker", "tag", backup_tag, old_image], check=False, timeout=60)
        write_node_config(NODE_DIR, node_port=int(state.get("node_port", NODE_PORT)), secret=secret, image=old_image, runner=runner)
        compose(runner, NODE_DIR, "up", "-d", check=False)
        if rollback_tagged:
            runner.run(["docker", "rmi", backup_tag], check=False, timeout=60)
        raise
    new_id_result = runner.run(["docker", "image", "inspect", target_image, "--format", "{{.Id}}"], check=False, timeout=60)
    if rollback_tagged:
        runner.run(["docker", "rmi", backup_tag], check=False, timeout=60)
    StateStore().save({**state, "image": target_image, "image_id": new_id_result.stdout.strip(), "last_update": time.time()})
    step("Обновление", "ok")
    return 0


def uninstall(confirmed: bool) -> int:
    _root_check()
    state = _load_state()
    if not confirmed:
        print("Будут удалены только ресурсы из install-state.json; чужие файлы и правила firewall сохранятся.")
        if input("Введите UNINSTALL для продолжения: ").strip() != "UNINSTALL":
            print("Отменено.")
            return 0
    runner = _runner()
    if (NODE_DIR / "docker-compose.yml").exists():
        compose(runner, NODE_DIR, "down", check=False)
    remove_managed_firewall(state.get("created_firewall", []), runner, int(state.get("node_port", NODE_PORT)))
    for item in reversed(state.get("backups", [])):
        source, backup = Path(item["source"]), Path(item["backup"])
        if backup.exists():
            source.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(backup, source)
    for value in sorted(state.get("created_paths", []), key=len, reverse=True):
        path = Path(value)
        if path.is_symlink() or path.is_file():
            path.unlink(missing_ok=True)
        elif path.is_dir():
            shutil.rmtree(path, ignore_errors=True) if path in (SITE_ROOT, INSTALLER_DIR, NODE_LOG_DIR) else path.rmdir()
    if state.get("certificate_created") and state.get("domain"):
        runner.run(["certbot", "delete", "--cert-name", state["domain"], "--non-interactive"], check=False, timeout=120)
    owned_packages = list(dict.fromkeys(state.get("installed_packages", []) + state.get("docker_packages", [])))
    if owned_packages:
        runner.run(["apt-get", "remove", "-y", "--purge", *owned_packages], check=False, timeout=900)
    StateStore().remove()
    print("Удалены только ресурсы, отмеченные установщиком как созданные. Чужие файлы и firewall-правила сохранены.")
    return 0


def logs() -> int:
    _root_check()
    _load_state()
    runner = _runner()
    return runner.stream(["docker", "compose", "-f", str(NODE_DIR / "docker-compose.yml"), "logs", "--tail=200", "-f"], check=False)


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
            domain = _read_interactive("Домен ноды: ")
            normalize_domain(domain)
            secret = _read_interactive("Ключ ноды из панели Remnawave: ", secret=True)
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
