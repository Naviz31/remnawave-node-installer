from .constants import FAIL2BAN_CONFIG, SSHD_HARDENING_CONFIG, SYSCTL_CONFIG
from .system import CommandRunner
from pathlib import Path
from typing import Callable, Optional


FAIL2BAN_JAIL = "\n".join([
    "[sshd]", "enabled = true", "backend = systemd", "maxretry = 5", "findtime = 10m", "bantime = 1h",
    "bantime.increment = true", "bantime.factor = 2", "bantime.maxtime = 7d", "",
])
# Mild limits only: no IP allow-list and no change to the authentication methods, so a roaming admin is never locked out.
SSHD_HARDENING = "\n".join(["MaxStartups 60:30:200", "LoginGraceTime 20", "MaxAuthTries 4", "ClientAliveInterval 30", "ClientAliveCountMax 6", ""])
SYSCTL_PROTECTION = "\n".join([
    "net.ipv4.tcp_syncookies = 1", "net.ipv4.tcp_max_syn_backlog = 4096", "net.ipv4.tcp_synack_retries = 3", "net.ipv4.tcp_fin_timeout = 30", "",
])


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
    FAIL2BAN_CONFIG.write_text(FAIL2BAN_JAIL, encoding="utf-8")
    if not existed and on_created:
        on_created(FAIL2BAN_CONFIG)
    FAIL2BAN_CONFIG.chmod(0o644)
    runner.run(["systemctl", "enable", "--now", "fail2ban"], timeout=60)
    runner.run(["fail2ban-client", "reload"], check=False, timeout=60)
    return True


def configure_ssh_limits(runner: CommandRunner, backup=None, on_created: Optional[Callable[[Path], None]] = None) -> bool:
    """Drop-in with connection limits for sshd. The file is validated with `sshd -t` and removed again if sshd rejects it."""
    if not runner.exists("sshd"):
        return False
    existed = SSHD_HARDENING_CONFIG.exists()
    if backup:
        backup(SSHD_HARDENING_CONFIG)
    SSHD_HARDENING_CONFIG.parent.mkdir(parents=True, exist_ok=True)
    previous = SSHD_HARDENING_CONFIG.read_text(encoding="utf-8") if existed else None
    SSHD_HARDENING_CONFIG.write_text(SSHD_HARDENING, encoding="utf-8")
    SSHD_HARDENING_CONFIG.chmod(0o644)
    if runner.run(["sshd", "-t"], check=False, timeout=30).returncode != 0:
        if previous is None:
            SSHD_HARDENING_CONFIG.unlink()
        else:
            SSHD_HARDENING_CONFIG.write_text(previous, encoding="utf-8")
        return False
    if not existed and on_created:
        on_created(SSHD_HARDENING_CONFIG)
    for unit in ("ssh", "sshd"):
        if runner.run(["systemctl", "reload", unit], check=False, timeout=60).returncode == 0:
            break
    return True


def configure_kernel_protection(runner: CommandRunner, on_created: Optional[Callable[[Path], None]] = None) -> bool:
    """SYN-flood protection through sysctl; takes effect immediately and survives reboots."""
    if not runner.exists("sysctl"):
        return False
    existed = SYSCTL_CONFIG.exists()
    SYSCTL_CONFIG.parent.mkdir(parents=True, exist_ok=True)
    SYSCTL_CONFIG.write_text(SYSCTL_PROTECTION, encoding="utf-8")
    SYSCTL_CONFIG.chmod(0o644)
    if not existed and on_created:
        on_created(SYSCTL_CONFIG)
    runner.run(["sysctl", "-p", str(SYSCTL_CONFIG)], check=False, timeout=30)
    return True
