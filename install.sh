#!/usr/bin/env bash
set -Eeuo pipefail

REPO_OWNER="Naviz31"
REPO_NAME="remnawave-node-installer"
# Keep the remote bootstrap independent from a moving branch. Update both values
# together when publishing a new installer source revision.
REPO_REF="v1.0.5-source"
REPO_SHA256="ff79715bbcb067cdad646352af2f2dc01701f8103091c735c962e120b4352eff"

die() {
  printf '\033[31m[✗] %s\033[0m\n' "$1" >&2
  exit 1
}

if [[ "$(id -u)" -ne 0 ]]; then
  die "Запустите установщик от root: sudo bash install.sh"
fi

# A previous rollback/uninstall may have removed the directory from which the
# caller started. Continue from a stable directory so Python and error
# handlers do not inherit a deleted cwd.
cd /

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
  command -v sha256sum >/dev/null 2>&1 || die "Не найден sha256sum для проверки bootstrap-архива"
  curl -fsSL "https://github.com/${REPO_OWNER}/${REPO_NAME}/archive/${REPO_REF}.tar.gz" -o "$archive"
  actual_sha256="$(sha256sum "$archive" | awk '{print $1}')"
  [[ "$actual_sha256" == "$REPO_SHA256" ]] || die "Контрольная сумма bootstrap-архива не совпала"
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
if [[ -r /dev/tty ]]; then
  exec python3 -m remnawave_node.cli "${@:-install}" </dev/tty
fi
exec python3 -m remnawave_node.cli "${@:-install}"
