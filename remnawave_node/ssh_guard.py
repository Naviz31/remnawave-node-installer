from .constants import FAIL2BAN_CONFIG
from .system import CommandRunner
from pathlib import Path
from typing import Callable, Optional


def detect_ssh_port(runner: CommandRunner) -> int:
    if runner.exists("sshd"):
        result = runner.run(["sshd", "-T"], check=False, timeout=30)
        for line in result.stdout.splitlines():
            if line.lower().startswith("port "):
                try:
                    return int(line.split()[1])
                except (IndexError, ValueError):
                    break
    return 22


def configure_fail2ban(runner: CommandRunner, backup=None, on_created: Optional[Callable[[Path], None]] = None) -> bool:
    if not runner.exists("fail2ban-client"):
        return False
    existed = FAIL2BAN_CONFIG.exists()
    if backup:
        backup(FAIL2BAN_CONFIG)
    FAIL2BAN_CONFIG.parent.mkdir(parents=True, exist_ok=True)
    FAIL2BAN_CONFIG.write_text("[sshd]\nenabled = true\nbackend = systemd\nmaxretry = 5\nfindtime = 10m\nbantime = 1h\n", encoding="utf-8")
    if not existed and on_created:
        on_created(FAIL2BAN_CONFIG)
    FAIL2BAN_CONFIG.chmod(0o644)
    runner.run(["systemctl", "enable", "--now", "fail2ban"], timeout=60)
    runner.run(["fail2ban-client", "reload"], check=False, timeout=60)
    return True
