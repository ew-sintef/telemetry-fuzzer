#!/bin/ash

# start_monitors.sh
#
# Usage:
#   start_monitors.sh <service>
#
# Services:
#   http  - uhttpd on tcp/80
#   dns   - dnsmasq on udp/53
#   ssh   - dropbear on tcp/22
#   sip   - example "sipd" on udp/5060 (adjust as needed)
#
# Environment variables (optional):
#   LOG_DIR     - default /tmp/fuzz/logs
#   TCPDUMP_IF  - interface for watchdog tcpdump (e.g. "any" or "br-lan")
#   CPU_THRESHOLD, MEM_THRESHOLD - for system_monitor.sh

SERVICE="$1"
if [ -z "$SERVICE" ]; then
    echo "Usage: $0 <http|dns|ssh|sip>" >&2
    exit 1
fi

LOG_DIR="${LOG_DIR:-/tmp/fuzz/logs}"

BASE_DIR="/tmp/fuzz"
mkdir -p "$LOG_DIR"

SYSTEM_MON="$BASE_DIR/system_monitor.sh"
PROC_MON="$BASE_DIR/process_monitor.sh"
WATCHDOG="$BASE_DIR/watchdog.sh"

# Sanity check scripts
for f in "$SYSTEM_MON" "$PROC_MON" "$WATCHDOG"; do
    if [ ! -x "$f" ]; then
        echo "Required script not found or not executable: $f" >&2
    fi
done

start_if_not_running() {
    # $1: match string (for pgrep -f)
    # $2: command to start
    MATCH="$1"
    CMD="$2"

    if pgrep -f "$MATCH" >/dev/null 2>&1; then
        echo "Already running: $MATCH"
    else
        echo "Starting: $CMD"
        # Run in background
        sh -c "$CMD &"
    fi
}

case "$SERVICE" in
    http)
        INIT_NAME="uhttpd"
        PROC_NAME="uhttpd"
        PROTO="tcp"
        PORT="80"
        HEALTHCHECK='wget -qO- http://127.0.0.1/ >/dev/null'
        ;;
    dns)
        INIT_NAME="dnsmasq"
        PROC_NAME="dnsmasq"
        PROTO="udp"
        PORT="53"
        HEALTHCHECK='nslookup openwrt.lan 127.0.0.1 >/dev/null'
        ;;
    ssh)
        INIT_NAME="dropbear"
        PROC_NAME="dropbear"
        PROTO="tcp"
        PORT="22"
        # Simple TCP check. BusyBox nc often present as "nc"
        HEALTHCHECK='nc -z 127.0.0.1 22 >/dev/null 2>&1'
        ;;
    sip)
        # Adjust these to your actual SIP daemon/init script
        INIT_NAME="sipd"
        PROC_NAME="sipd"
        PROTO="udp"
        PORT="5060"
        # Very basic healthcheck; replace with something smarter (e.g. sipsak) if available
        HEALTHCHECK='echo | nc -u -w1 127.0.0.1 5060 >/dev/null 2>&1'
        ;;
    *)
        echo "Unknown service: $SERVICE" >&2
        exit 1
        ;;
esac

echo "Starting monitors for service: $SERVICE"
echo "  INIT_NAME = $INIT_NAME"
echo "  PROC_NAME = $PROC_NAME"
echo "  PROTO     = $PROTO"
echo "  PORT      = $PORT"
echo "  LOG_DIR   = $LOG_DIR"
echo

# 1) System monitor (CPU + MEM)
if [ -x "$SYSTEM_MON" ]; then
    start_if_not_running "system_monitor.sh" \
        "LOG_DIR='$LOG_DIR' CPU_THRESHOLD='80' MEM_THRESHOLD='75' '$SYSTEM_MON'"
else
    echo "Skipping system monitor, not found: $SYSTEM_MON"
fi

# 2) Process monitor for this service
if [ -x "$PROC_MON" ]; then
    start_if_not_running "process_monitor.sh $PROC_NAME" \
        "LOG_DIR='$LOG_DIR' '$PROC_MON' '$PROC_NAME'"
else
    echo "Skipping process monitor, not found: $PROC_MON"
fi

# 3) Watchdog for this service
if [ -x "$WATCHDOG" ]; then
    start_if_not_running "watchdog.sh $INIT_NAME $PROTO $PORT" \
        "LOG_DIR='$LOG_DIR' '$WATCHDOG' '$INIT_NAME' '$PROTO' '$PORT' $HEALTHCHECK"
else
    echo "Skipping watchdog, not found: $WATCHDOG"
fi

echo "Monitor launch sequence complete."
