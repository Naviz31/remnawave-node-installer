import os
import re
import tempfile
from pathlib import Path
from typing import Iterable, Mapping


SECRET_MARKER = "[REDACTED]"


def redact(value: str, secrets: Iterable[str] = ()) -> str:
    """Remove secret values from any text before it reaches a log or UI."""
    result = value
    for secret in secrets:
        if secret:
            result = result.replace(secret, SECRET_MARKER)
    result = re.sub(r"(?im)(SECRET_KEY|SSL_CERT)\s*=\s*[^\s\r\n]+", r"\1=" + SECRET_MARKER, result)
    return result


def write_private(path: Path, content: str, *, mode: int = 0o600) -> None:
    """Atomically write a private file without following an existing symlink."""
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temp_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=str(path.parent), text=True)
    try:
        os.fchmod(fd, mode)
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp_name, path)
        os.chmod(path, mode)
    except Exception:
        try:
            os.unlink(temp_name)
        except FileNotFoundError:
            temp_name = ""
        raise


def read_env_file(path: Path) -> Mapping[str, str]:
    values = {}
    if not path.exists():
        return values
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        values[key.strip()] = value.strip().strip('"').strip("'")
    return values


def env_line(key: str, value: str) -> str:
    escaped = value.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "")
    return f'{key}="{escaped}"'
