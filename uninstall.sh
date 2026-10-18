#!/usr/bin/env bash
set -Eeuo pipefail

if ! command -v dpkg-query >/dev/null 2>&1; then
    printf 'uninstall.sh: dpkg-query is required (Ubuntu or Debian).\n' >&2
    exit 1
fi
if ! command -v apt-get >/dev/null 2>&1; then
    printf 'uninstall.sh: apt-get is required (Ubuntu or Debian).\n' >&2
    exit 1
fi
if ! dpkg-query -W -f='${Status}' opsai-cli 2>/dev/null | grep -q 'install ok installed'; then
    printf 'OpsAI is not installed as a Debian package.\n'
    exit 0
fi

if [[ "$(id -u)" -eq 0 ]]; then
    apt-get purge -y opsai-cli
elif command -v sudo >/dev/null 2>&1; then
    sudo apt-get purge -y opsai-cli
else
    printf 'uninstall.sh: Run as root or install sudo to continue.\n' >&2
    exit 1
fi
