#!/usr/bin/env bash
set -Eeuo pipefail

REPO_OWNER="Naviz31"
REPO_NAME="remnawave-node-installer"
REPO_REF="main"

die() {
  printf '\033[31m[✗] %s\033[0m\n' "$1" >&2
  exit 1
}

if [[ "$(id -u)" -ne 0 ]]; then
  die "Запустите установщик от root: sudo bash install.sh"
fi

SCRIPT_DIR=""
if [[ -n "${BASH_SOURCE[0]:-}" ]]; then
  candidate="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" 2>/dev/null && pwd -P || true)"
  if [[ -f "$candidate/remnawave_node/cli.py" ]]; then
    SCRIPT_DIR="$candidate"
  fi
fi

if [[ -z "$SCRIPT_DIR" ]]; then
  command -v curl >/dev/null 2>&1 || {
    command -v apt-get >/dev/null 2>&1 || die "Нужны curl или apt-get для bootstrap"
    apt-get update
    apt-get install -y curl ca-certificates tar
  }
  command -v tar >/dev/null 2>&1 || {
    command -v apt-get >/dev/null 2>&1 || die "Не найден tar"
    apt-get update
    apt-get install -y tar
  }
  temp_dir="$(mktemp -d -t remnawave-node-installer.XXXXXX)"
  cleanup() { rm -rf -- "$temp_dir"; }
  trap cleanup EXIT
  archive="$temp_dir/source.tar.gz"
  curl -fsSL "https://github.com/${REPO_OWNER}/${REPO_NAME}/archive/refs/heads/${REPO_REF}.tar.gz" -o "$archive"
  tar -xzf "$archive" -C "$temp_dir"
  SCRIPT_DIR="$(find "$temp_dir" -mindepth 1 -maxdepth 1 -type d -name "${REPO_NAME}-*" -print -quit)"
  [[ -n "$SCRIPT_DIR" && -f "$SCRIPT_DIR/remnawave_node/cli.py" ]] || die "Не удалось распаковать исходный код установщика"
fi

command -v python3 >/dev/null 2>&1 || {
  command -v apt-get >/dev/null 2>&1 || die "Не найден python3 и недоступен apt-get"
  apt-get update
  apt-get install -y python3
}

export PYTHONPATH="$SCRIPT_DIR${PYTHONPATH:+:$PYTHONPATH}"
exec python3 -m remnawave_node.cli "${@:-install}"
