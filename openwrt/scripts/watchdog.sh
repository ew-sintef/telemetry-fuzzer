#!/bin/ash

#
# watchdog.sh
#
# Usage:
#   watchdog.sh <init_name> <tcp|udp> <port> [healthcheck command...]
#
# Env:
#   LOG_DIR            default /tmp/fuzz/logs
#   SNAPSHOT_CMD       default /tmp/fuzz/snapshot.sh
#   CHECK_INTERVAL     default 3
#   SNAPSHOT_COOLDOWN  default 60
#   MAX_FAILURES       default 3
#

INIT_NAME="$1"
PROTO="$2"
PORT="$3"

shift 3

CHECK_CMD="$*"

if [ -z "$INIT_NAME" ] || [ -z "$PROTO" ] || [ -z "$PORT" ]; then
    echo "Usage: $0 <init_name> <tcp|udp> <port> [healthcheck command...]" >&2
    exit 1
fi

LOG_DIR="${LOG_DIR:-/tmp/fuzz/logs}"
SNAPSHOT_CMD="${SNAPSHOT_CMD:-/tmp/fuzz/snapshot.sh}"

CHECK_INTERVAL="${CHECK_INTERVAL:-3}"
SNAPSHOT_COOLDOWN="${SNAPSHOT_COOLDOWN:-60}"

MAX_FAILURES="${MAX_FAILURES:-3}"

mkdir -p "$LOG_DIR"

LOG_FILE="$LOG_DIR/${INIT_NAME}_watchdog.log"

last_snapshot_ts=0

PORT_FAILURES=0
HEALTH_FAILURES=0

stamp() {
    date '+%Y-%m-%d %H:%M:%S'
}

now_ts() {
    date '+%s'
}

log() {
    echo "$(stamp) [$INIT_NAME] $*" | tee -a "$LOG_FILE"
}

is_listening() {

    if command -v ss >/dev/null 2>&1; then

        ss -luna 2>/dev/null \
            | grep -E "[[:space:]]$PROTO[[:space:]].*:$PORT[[:space:]]" \
            >/dev/null 2>&1

    else

        netstat -luna 2>/dev/null \
            | grep -E "[[:space:]]$PROTO[[:space:]].*:$PORT[[:space:]]" \
            >/dev/null 2>&1

    fi

    return $?
}

take_snapshot_rate_limited() {

    ts="$(now_ts)"

    delta=$((ts - last_snapshot_ts))

    if [ "$delta" -lt "$SNAPSHOT_COOLDOWN" ]; then

        log "snapshot skipped (cooldown ${SNAPSHOT_COOLDOWN}s, last ${delta}s ago)"

        return 0
    fi

    if [ -x "$SNAPSHOT_CMD" ]; then

        SNAP_FILE="$($SNAPSHOT_CMD 2>/dev/null)"

        last_snapshot_ts="$ts"

        log "snapshot taken: $SNAP_FILE"

    else

        log "snapshot command not executable: $SNAPSHOT_CMD"

    fi
}

restart_service() {

    log "restarting service: /etc/init.d/$INIT_NAME restart"

    /etc/init.d/"$INIT_NAME" restart \
        >>"$LOG_DIR/${INIT_NAME}_restart.log" 2>&1

    rc=$?

    log "restart rc=$rc"

    PORT_FAILURES=0
    HEALTH_FAILURES=0
}

log "watchdog started (proto=$PROTO port=$PORT init=$INIT_NAME check_interval=${CHECK_INTERVAL}s snapshot_cooldown=${SNAPSHOT_COOLDOWN}s max_failures=${MAX_FAILURES})"

while :; do

    #
    # Port check
    #
    if ! is_listening; then

        PORT_FAILURES=$((PORT_FAILURES + 1))

        log "port $PORT/$PROTO is NOT listening (${PORT_FAILURES}/${MAX_FAILURES})"

    else

        if [ "$PORT_FAILURES" -gt 0 ]; then
            log "port check recovered after ${PORT_FAILURES} failure(s)"
        fi

        PORT_FAILURES=0

    fi

    #
    # Health check
    #
    if [ -n "$CHECK_CMD" ]; then

        sh -c "$CHECK_CMD"

        RC="$?"

        if [ "$RC" -ne 0 ]; then

            HEALTH_FAILURES=$((HEALTH_FAILURES + 1))

            log "healthcheck failed (${HEALTH_FAILURES}/${MAX_FAILURES}) (rc=$RC): $CHECK_CMD"

        else

            if [ "$HEALTH_FAILURES" -gt 0 ]; then
                log "healthcheck recovered after ${HEALTH_FAILURES} failure(s)"
            fi

            HEALTH_FAILURES=0

        fi
    fi

    #
    # Restart threshold reached?
    #
    if [ "$PORT_FAILURES" -ge "$MAX_FAILURES" ] || \
       [ "$HEALTH_FAILURES" -ge "$MAX_FAILURES" ]; then

        log "failure threshold reached (port_failures=$PORT_FAILURES health_failures=$HEALTH_FAILURES)"

        take_snapshot_rate_limited

        restart_service

        sleep 3
    fi

    sleep "$CHECK_INTERVAL"

done
