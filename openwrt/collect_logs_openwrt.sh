#!/usr/bin/env bash
set -euo pipefail

# Usage:
#   ./openwrt/collect_logs_openwrt.sh [user@host] [label]
#
# Examples:
#   ./openwrt/collect_logs_openwrt.sh root@192.168.1.1 http_test01
#   ./openwrt/collect_logs_openwrt.sh root@192.168.1.1

HOST="${1:-root@192.168.1.1}"
LABEL="${2:-openwrt_$(date +%Y%m%d-%H%M%S)}"

# repo root = parent of openwrt/
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

DEST="$REPO_ROOT/out/openwrt/$LABEL"
mkdir -p "$DEST"

echo "[*] Collecting OpenWrt artifacts from $HOST"
echo "[*] Destination: $DEST"

# Logs are the main value
scp -r "$HOST:/tmp/fuzz/logs" "$DEST/" 2>/dev/null || echo "[!] No /tmp/fuzz/logs found or copy failed"

# Optional dirs
#scp -r "$HOST:/tmp/fuzz/cores" "$DEST/" 2>/dev/null || true
#scp -r "$HOST:/tmp/fuzz/pcaps" "$DEST/" 2>/dev/null || true

echo "[*] Done. Collected:"
find "$DEST" -maxdepth 2 -type f | sed "s|^|  |"
