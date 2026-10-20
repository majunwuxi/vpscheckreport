#!/usr/bin/env bash
set -Eeuo pipefail
(( EUID == 0 )) || { echo 'Run with sudo'; exit 1; }
command -v git >/dev/null || { apt-get update && apt-get install -y git; }
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
git clone -q --depth 1 https://github.com/majunwuxi/vpscheckreport.git "$tmp/src"
exec bash "$tmp/src/bin/install.sh"
