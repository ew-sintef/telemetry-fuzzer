#!/bin/ash

# Usage: process_monitor.sh <process_name>
# Example: ./process_monitor.sh uhttpd

if [ $# -ne 1 ]; then
    echo "Usage: $0 <process_name>" >&2
    exit 1
fi

PROCESS="$1"
LOG_DIR="${LOG_DIR:-/tmp/fuzz/logs}"
mkdir -p "$LOG_DIR"

LOG_FILE="$LOG_DIR/${PROCESS}_procmon.log"

log() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') [procmon:$PROCESS] $*" | tee -a "$LOG_FILE"
}

get_pids() {
    # BusyBox pgrep is usually present on OpenWrt; fallback to ps|grep if needed.
    if command -v pgrep >/dev/null 2>&1; then
        pgrep "$PROCESS" 2>/dev/null
    else
        ps w 2>/dev/null | grep "$PROCESS" | grep -v grep | awk '{print $1}'
    fi
}

log "Starting process monitor for '$PROCESS'"

LAST_STATE="unknown"

while :; do
    PIDS="$(get_pids)"
    if [ -z "$PIDS" ]; then
        if [ "$LAST_STATE" != "down" ]; then
            log "Process is NOT running"
            log "Recent dmesg (last 20 lines):"
            dmesg | tail -n 20 >> "$LOG_FILE" 2>/dev/null
            LAST_STATE="down"
        fi
    else
        if [ "$LAST_STATE" != "up" ]; then
            log "Process is running with PIDs: $PIDS"
            LAST_STATE="up"
        fi
    fi
    sleep 1
done
