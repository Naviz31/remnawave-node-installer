import logging
from pathlib import Path
from typing import Iterable

from .security import redact


class RedactingFormatter(logging.Formatter):
    def __init__(self, secrets: Iterable[str] = ()):
        super().__init__("%(asctime)s %(levelname)s %(message)s", "%Y-%m-%dT%H:%M:%S%z")
        self.secrets = tuple(secrets)

    def format(self, record: logging.LogRecord) -> str:
        return redact(super().format(record), self.secrets)


def configure_logger(log_path: Path, secrets: Iterable[str] = ()) -> logging.Logger:
    log_path.parent.mkdir(parents=True, exist_ok=True)
    logger = logging.getLogger("remnawave-node")
    logger.setLevel(logging.INFO)
    logger.handlers.clear()
    handler = logging.FileHandler(log_path, encoding="utf-8")
    handler.setFormatter(RedactingFormatter(secrets))
    logger.addHandler(handler)
    return logger
