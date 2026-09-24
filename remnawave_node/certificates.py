from pathlib import Path
from typing import Callable, Optional

from .constants import CERTBOT_LIVE_DIR
from .errors import InstallerError
from .system import CommandRunner


def certificate_exists(domain: str) -> bool:
    return (CERTBOT_LIVE_DIR / domain / "fullchain.pem").is_file() and (CERTBOT_LIVE_DIR / domain / "privkey.pem").is_file()


def issue_certificate(domain: str, runner: CommandRunner) -> bool:
    if certificate_exists(domain):
        return False
    runner.run([
        "certbot", "certonly", "--webroot", "-w", "/var/www/remnawave-node",
        "-d", domain, "--non-interactive", "--agree-tos",
        "--register-unsafely-without-email", "--keep-until-expiring",
    ], timeout=300)
    if not certificate_exists(domain):
        raise InstallerError("certbot завершился без ожидаемых файлов сертификата", stage="tls")
    return True


def install_renewal_hook(domain: str, runner: CommandRunner, on_created: Optional[Callable[[Path], None]] = None) -> bool:
    hook = Path("/etc/letsencrypt/renewal-hooks/deploy/remnawave-node-reload")
    existed = hook.exists()
    hook.parent.mkdir(parents=True, exist_ok=True)
    hook.write_text("#!/bin/sh\nsystemctl reload nginx\n", encoding="utf-8")
    if not existed and on_created:
        on_created(hook)
    hook.chmod(0o755)
    try:
        result = runner.run(["certbot", "renew", "--dry-run", "--non-interactive"], check=False, timeout=300)
    except InstallerError:
        return False
    return result.returncode == 0
