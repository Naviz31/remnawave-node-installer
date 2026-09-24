import json
import shutil
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

from .constants import BACKUP_DIR, STATE_DIR, STATE_FILE
from .security import write_private


def _json_default(value: Any) -> str:
    if isinstance(value, Path):
        return str(value)
    raise TypeError(f"unsupported state value: {type(value)!r}")


class StateStore:
    def __init__(self, path: Path = STATE_FILE):
        self.path = path

    def exists(self) -> bool:
        return self.path.is_file()

    def load(self) -> Dict[str, Any]:
        if not self.exists():
            return {}
        return json.loads(self.path.read_text(encoding="utf-8"))

    def save(self, data: Dict[str, Any]) -> None:
        STATE_DIR.mkdir(parents=True, exist_ok=True)
        write_private(self.path, json.dumps(data, ensure_ascii=False, indent=2, default=_json_default) + "\n", mode=0o600)

    def remove(self) -> None:
        self.path.unlink(missing_ok=True)


@dataclass
class InstallTransaction:
    state: StateStore = field(default_factory=StateStore)
    data: Dict[str, Any] = field(default_factory=dict)
    backup_root: Optional[Path] = None
    committed: bool = False

    def begin(self, *, domain: str, node_port: int, image: str, panel_ips: List[str]) -> None:
        stamp = time.strftime("%Y%m%d-%H%M%S")
        self.backup_root = BACKUP_DIR / stamp
        self.backup_root.mkdir(parents=True, exist_ok=True)
        self.data = {
            "schema": 1,
            "status": "in_progress",
            "created_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "domain": domain,
            "node_port": node_port,
            "image": image,
            "panel_ips": panel_ips,
            "secret_configured": True,
            "backup_root": str(self.backup_root),
            "created_paths": [],
            "created_services": [],
            "created_firewall": [],
            "backups": [],
            "preexisting": {},
        }
        self.state.save(self.data)

    def mark_preexisting(self, key: str, value: Any) -> None:
        self.data.setdefault("preexisting", {})[key] = value
        self.state.save(self.data)

    def record_path(self, path: Path) -> None:
        value = str(path)
        if value not in self.data.setdefault("created_paths", []):
            self.data["created_paths"].append(value)
        self.state.save(self.data)

    def record_service(self, name: str) -> None:
        if name not in self.data.setdefault("created_services", []):
            self.data["created_services"].append(name)
        self.state.save(self.data)

    def record_firewall(self, item: str) -> None:
        if item not in self.data.setdefault("created_firewall", []):
            self.data["created_firewall"].append(item)
        self.state.save(self.data)

    def backup_file(self, path: Path) -> Optional[Path]:
        if not path.exists() or not self.backup_root:
            return None
        target = self.backup_root / path.as_posix().lstrip("/").replace("/", "_")
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(path, target)
        self.data.setdefault("backups", []).append({"source": str(path), "backup": str(target)})
        self.state.save(self.data)
        return target

    def commit(self) -> None:
        self.data["status"] = "installed"
        self.data["completed_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        self.committed = True
        self.state.save(self.data)

    def mark_rollback(self) -> None:
        self.data["status"] = "rolled_back"
        self.data["rolled_back_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        self.state.save(self.data)

    def restore_backups(self) -> None:
        for item in reversed(self.data.get("backups", [])):
            source = Path(item["source"])
            backup = Path(item["backup"])
            if backup.exists():
                source.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(backup, source)

    def created_paths(self) -> Iterable[Path]:
        for value in self.data.get("created_paths", []):
            yield Path(value)
