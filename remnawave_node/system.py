import os
import platform
import shutil
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence

from .errors import InstallerError
from .logging_utils import redact


@dataclass
class CommandResult:
    returncode: int
    stdout: str = ""
    stderr: str = ""


class CommandRunner:
    def __init__(self, logger=None, secrets: Iterable[str] = ()):
        self.logger = logger
        self.secrets = tuple(secrets)

    def run(self, args: Sequence[str], *, check: bool = True, timeout: int = 300, input_text: Optional[str] = None, env: Optional[Dict[str, str]] = None) -> CommandResult:
        shown = redact(" ".join(args), self.secrets)
        if self.logger:
            self.logger.info("$ %s", shown)
        try:
            completed = subprocess.run(args, input=input_text, text=True, capture_output=True, timeout=timeout, env=env)
        except (OSError, subprocess.TimeoutExpired) as exc:
            message = redact(str(exc), self.secrets)
            if self.logger:
                self.logger.error("command error: %s", message)
            raise InstallerError(message, stage="command") from exc
        output = redact(completed.stdout or "", self.secrets)
        error = redact(completed.stderr or "", self.secrets)
        if self.logger and output:
            self.logger.info("stdout: %s", output.strip())
        if self.logger and error:
            self.logger.info("stderr: %s", error.strip())
        result = CommandResult(completed.returncode, output, error)
        if check and completed.returncode != 0:
            raise InstallerError(f"команда завершилась с кодом {completed.returncode}: {shown}", stage="command", hint=error.strip()[-500:])
        return result

    def exists(self, command: str) -> bool:
        return shutil.which(command) is not None


def read_os_release(path: Path = Path("/etc/os-release")) -> Dict[str, str]:
    data: Dict[str, str] = {}
    if not path.exists():
        return data
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        if "=" not in raw_line or raw_line.startswith("#"):
            continue
        key, value = raw_line.split("=", 1)
        data[key] = value.strip().strip('"')
    return data


def memory_bytes() -> int:
    try:
        pages = os.sysconf("SC_PHYS_PAGES")
        page_size = os.sysconf("SC_PAGE_SIZE")
        return pages * page_size
    except (ValueError, OSError):
        return 0


def public_ip(runner: CommandRunner, family: int = 4) -> Optional[str]:
    candidates = ["https://api4.ipify.org"] if family == 4 else ["https://api6.ipify.org"]
    for url in candidates:
        if not runner.exists("curl"):
            return None
        result = runner.run(["curl", "-4" if family == 4 else "-6", "-fsS", "--max-time", "5", url], check=False, timeout=10)
        value = result.stdout.strip()
        if result.returncode == 0 and value:
            return value
    return None


def port_listeners(runner: CommandRunner) -> Dict[int, List[str]]:
    result = runner.run(["ss", "-lntH"], check=False, timeout=10)
    listeners: Dict[int, List[str]] = {}
    for line in result.stdout.splitlines():
        fields = line.split()
        if len(fields) < 4 or ":" not in fields[3]:
            continue
        try:
            port = int(fields[3].rsplit(":", 1)[1].strip("]"))
        except ValueError:
            continue
        listeners.setdefault(port, []).append(fields[3])
    return listeners


def is_service_active(runner: CommandRunner, service: str) -> bool:
    result = runner.run(["systemctl", "is-active", "--quiet", service], check=False, timeout=10)
    return result.returncode == 0


def package_installed(package: str) -> bool:
    result = subprocess.run(["dpkg-query", "-W", "-f=${Status}", package], capture_output=True, text=True)
    return result.returncode == 0 and "install ok installed" in result.stdout
