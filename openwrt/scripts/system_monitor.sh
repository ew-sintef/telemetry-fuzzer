#!/bin/ash

# Simple system monitor for OpenWrt (CPU + memory)
# Logs when usage exceeds thresholds.
#
# Environment variables (optional):
#   CPU_THRESHOLD   - CPU usage percent (0-100), default 80
#   MEM_THRESHOLD   - Memory usage percent (0-100), default 75
#   INTERVAL        - seconds between checks, default 5
#   LOG_DIR         - default /tmp/fuzz/logs

CPU_THRESHOLD="${CPU_THRESHOLD:-80}"
MEM_THRESHOLD="${MEM_THRESHOLD:-75}"
INTERVAL="${INTERVAL:-5}"
LOG_DIR="${LOG_DIR:-/tmp/fuzz/logs}"

mkdir -p "$LOG_DIR"
LOG_FILE="$LOG_DIR/system_monitor.log"

log() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') [sysmon] $*" >> "$LOG_FILE"
}

read_cpu() {
    # Read /proc/stat cpu line
    set -- $(grep '^cpu ' /proc/stat)
    # Fields: cpu user nice system idle iowait irq softirq steal ...
    CPU_USER="$2"
    CPU_NICE="$3"
    CPU_SYSTEM="$4"
    CPU_IDLE="$5"
    CPU_IOWAIT="$6"
    CPU_IRQ="$7"
    CPU_SOFTIRQ="$8"
    CPU_TOTAL=$((CPU_USER + CPU_NICE + CPU_SYSTEM + CPU_IDLE + CPU_IOWAIT + CPU_IRQ + CPU_SOFTIRQ))
}

calc_cpu_usage() {
    # usage = (delta_total - delta_idle) * 100 / delta_total
    local diff_total=$((CPU_TOTAL - PREV_TOTAL))
    local diff_idle=$((CPU_IDLE - PREV_IDLE))

    if [ "$diff_total" -gt 0 ]; then
        CPU_USAGE=$(((diff_total - diff_idle) * 100 / diff_total))
    else
        CPU_USAGE=0
    fi
}

read_mem() {
    # Parse MemTotal and MemAvailable from /proc/meminfo
    MEM_TOTAL_KB=0
    MEM_AVAIL_KB=0
    while read line; do
        case "$line" in
            MemTotal:*)
                set -- $line
                MEM_TOTAL_KB="$2"
                ;;
            MemAvailable:*)
                set -- $line
                MEM_AVAIL_KB="$2"
                ;;
        esac
        if [ "$MEM_TOTAL_KB" -ne 0 ] && [ "$MEM_AVAIL_KB" -ne 0 ]; then
            break
        fi
    done < /proc/meminfo

    if [ "$MEM_TOTAL_KB" -gt 0 ]; then
        local used=$((MEM_TOTAL_KB - MEM_AVAIL_KB))
        MEM_USAGE=$((used * 100 / MEM_TOTAL_KB))
    else
        MEM_USAGE=0
    fi
}

log "System monitor started (CPU>=$CPU_THRESHOLD%, MEM>=$MEM_THRESHOLD%, interval=${INTERVAL}s)"

# Initialize CPU baseline
read_cpu
PREV_TOTAL="$CPU_TOTAL"
PREV_IDLE="$CPU_IDLE"

while :; do
    sleep "$INTERVAL"

    # CPU
    read_cpu
    calc_cpu_usage
    PREV_TOTAL="$CPU_TOTAL"
    PREV_IDLE="$CPU_IDLE"

    if [ "$CPU_USAGE" -ge "$CPU_THRESHOLD" ]; then
        log "CPU usage high: ${CPU_USAGE}%"
    fi

    # Memory
    read_mem
    if [ "$MEM_USAGE" -ge "$MEM_THRESHOLD" ]; then
        log "Memory usage high: ${MEM_USAGE}% (MemTotal=${MEM_TOTAL_KB}kB, MemAvailable=${MEM_AVAIL_KB}kB)"
    fi
done
