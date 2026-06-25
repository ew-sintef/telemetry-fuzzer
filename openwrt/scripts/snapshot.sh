#!/bin/ash

# snapshot.sh
# Take a quick system snapshot for fuzzing diagnostics.
# Writes to: $LOG_DIR/snap_YYYYMMDD_HHMMSS.log (default /tmp/fuzz/logs)

LOG_DIR="${LOG_DIR:-/tmp/fuzz/logs}"
mkdir -p "$LOG_DIR"

OUT="$LOG_DIR/snap_$(date +%Y%m%d_%H%M%S).log"

{
    echo "=== SNAPSHOT $(date) ==="
    echo
    echo "---- uname ----"
    uname -a 2>/dev/null

    echo
    echo "---- uptime ----"
    uptime 2>/dev/null

    echo
    echo "---- processes (ps w) ----"
    ps w 2>/dev/null

    echo
    echo "---- network sockets ----"
    if command -v ss >/dev/null 2>&1; then
        ss -an 2>/dev/null
    else
        netstat -an 2>/dev/null
    fi

    echo
    echo "---- memory (/proc/meminfo) ----"
    cat /proc/meminfo 2>/dev/null

    echo
    echo "---- disk usage (df -h) ----"
    df -h 2>/dev/null

    echo
    echo "---- kernel ring buffer (last 200 lines) ----"
    dmesg 2>/dev/null | tail -n 200

    echo
    echo "---- syslog (last 200 lines) ----"
    if command -v logread >/dev/null 2>&1; then
        logread 2>/dev/null | tail -n 200
    else
        echo "logread not available"
    fi
} > "$OUT" 2>&1

echo "$OUT"
