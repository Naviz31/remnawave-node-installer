import shutil
import sys
from contextlib import contextmanager
from typing import Iterator


RESET = "\033[0m"
GREEN = "\033[32m"
YELLOW = "\033[33m"
RED = "\033[31m"
CYAN = "\033[36m"
DIM = "\033[2m"


def color(text: str, tone: str) -> str:
    if not sys.stdout.isatty():
        return text
    return f"{tone}{text}{RESET}"


def title(text: str) -> None:
    width = min(max(shutil.get_terminal_size((88, 24)).columns, 56), 100)
    print()
    print(color("╭" + "─" * (width - 2) + "╮", CYAN))
    print(color("│" + text.center(width - 2) + "│", CYAN))
    print(color("╰" + "─" * (width - 2) + "╯", CYAN))


def step(label: str, state: str = "running", detail: str = "") -> None:
    symbol, tone = {"ok": ("✓", GREEN), "warn": ("!", YELLOW), "error": ("✗", RED), "running": ("→", CYAN)}.get(state, ("·", DIM))
    suffix = f"  {detail}" if detail else ""
    print(f"[{color(symbol, tone)}] {label}{suffix}")


def kv(label: str, value: str, state: str = "ok") -> None:
    tone = GREEN if state == "ok" else YELLOW if state == "warn" else RED
    print(f"  {label:<20} {color(value, tone)}")


def error_box(stage: str, reason: str, log_path: str, rolled_back: bool = True) -> None:
    title("Установка не завершена")
    print(f"  Этап                 {stage}")
    print(f"  Причина              {reason}")
    print(f"  Rollback             {'выполнен' if rolled_back else 'не требуется'}")
    print(f"  Подробный лог        {log_path}")
    print()


@contextmanager
def live_step(label: str) -> Iterator[None]:
    step(label, "running")
    try:
        yield
    except Exception:
        step(label, "error")
        raise
    else:
        step(label, "ok")
