#!/bin/ash

# stop_monitors.sh
#
# Stop monitoring processes started for fuzzing:
#   - system_monitor.sh
#   - process_monitor.sh
#   - watchdog.sh
#
# Usage:
#   ./stop_monitors.sh
#

LOG_DIR="${LOG_DIR:-/tmp/fuzz/logs}"
mkdir -p "$LOG_DIR"
LOG_FILE="$LOG_DIR/stop_monitors.log"

log() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') [stop_monitors] $*" | tee -a "$LOG_FILE"
}

kill_by_pattern() {
    PATTERN="$1"
    # Find PIDs whose command line matches PATTERN, but skip the grep itself
    PIDS="$(ps w | grep "$PATTERN" | grep -v grep | awk '{print $1}')"

    if [ -n "$PIDS" ]; then
        log "Killing processes for pattern '$PATTERN': $PIDS"
        kill $PIDS 2>/dev/null
    else
        log "No processes found for pattern '$PATTERN'"
    fi
}

log "Stopping monitoring scripts (system_monitor, process_monitor, watchdog)..."

kill_by_pattern "/tmp/fuzz/system_monitor.sh"
kill_by_pattern "/tmp/fuzz/process_monitor.sh"
kill_by_pattern "/tmp/fuzz/watchdog.sh"

log "Done."
