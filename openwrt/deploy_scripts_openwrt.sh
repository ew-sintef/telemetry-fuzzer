#!/usr/bin/env bash
set -euo pipefail

# Usage:
#   ./openwrt/deploy_scripts_openwrt.sh [user@host]
#
# Example:
#   ./openwrt/deploy_scripts_openwrt.sh root@192.168.1.1

HOST="${1:-root@192.168.1.1}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCRIPTS_SRC="$SCRIPT_DIR/scripts"

echo "[*] Deploying OpenWrt scripts to $HOST:/tmp/fuzz/"

ssh "$HOST" "mkdir -p /tmp/fuzz"
scp -r "$SCRIPTS_SRC"/* "$HOST:/tmp/fuzz/"

ssh "$HOST" "chmod +x /tmp/fuzz/*.sh"

echo "[*] Done. Remote /tmp/fuzz contains:"
ssh "$HOST" "ls -1 /tmp/fuzz"

