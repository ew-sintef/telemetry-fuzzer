#!/usr/bin/env bash
set -euo pipefail

: "${LOG_DIR:=/logs}"
: "${TARGET_IP:?TARGET_IP not set}"
: "${TARGET_PORT:?TARGET_PORT not set}"
: "${SCRIPT_PATH:?SCRIPT_PATH not set}"

echo "[*] Running fuzz script:"
echo "    SCRIPT_PATH = $SCRIPT_PATH"
echo "    TARGET_IP   = $TARGET_IP"
echo "    TARGET_PORT = $TARGET_PORT"
echo "    LOG_DIR     = $LOG_DIR"
echo

mkdir -p "$LOG_DIR"

# Make sure env vars are available to the Python script
export LOG_DIR TARGET_IP TARGET_PORT

exec python3 "$SCRIPT_PATH"
