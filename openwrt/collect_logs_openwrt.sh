#!/usr/bin/env bash

set -euo pipefail

HOST="${1:-root@192.168.1.1}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

echo
echo "Collect OpenWrt logs"
echo "===================="
echo

mapfile -t sessions < <(
    find "$REPO_ROOT/out" \
        -mindepth 2 \
        -maxdepth 2 \
        -type d \
        -printf '%T@ %p\n' |
    sort -rn |
    cut -d' ' -f2-
)

if [[ ${#sessions[@]} -eq 0 ]]; then
    echo "No fuzzing sessions found."
    exit 1
fi

echo "Recent fuzzing sessions:"
echo

for i in "${!sessions[@]}"
do
    printf "%2d) %s\n" \
        "$((i + 1))" \
        "${sessions[$i]}"
done

echo

read -rp "Select session number: " choice

if ! [[ "$choice" =~ ^[0-9]+$ ]]; then
    echo "Invalid selection."
    exit 1
fi

if (( choice < 1 || choice > ${#sessions[@]} )); then
    echo "Invalid selection."
    exit 1
fi

SESSION_DIR="${sessions[$((choice - 1))]}"

TARGET_LOG_DIR="$SESSION_DIR/target_logs"

mkdir -p "$TARGET_LOG_DIR"

echo
echo "Selected session:"
echo "  $SESSION_DIR"
echo

echo "Collecting logs from $HOST ..."
echo

scp -r \
    "$HOST:/tmp/fuzz/logs/" \
    "$TARGET_LOG_DIR/" \
    2>/dev/null || \
    echo "[!] No /tmp/fuzz/logs directory found"

echo

echo "Collected files:"
find "$TARGET_LOG_DIR" -type f || true

echo
echo "Regenerating summary..."
echo

python3 -B \
    "$REPO_ROOT/fuzzing_scripts/analysis/generate_summary.py" \
    --session "$SESSION_DIR"

echo
echo "Summary regenerated."
echo

if [[ -f "$SESSION_DIR/summary.txt" ]]; then

#    echo "============================================"
#    echo "SUMMARY"
#    echo "============================================"
    echo

    cat "$SESSION_DIR/summary.txt"

elif [[ -f "$SESSION_DIR/summary.md" ]]; then

    echo "============================================"
    echo "SUMMARY"
    echo "============================================"
    echo

    cat "$SESSION_DIR/summary.md"

fi

echo
echo "Session directory:"
echo "  $SESSION_DIR"

echo
echo "Summary files:"
echo "  $SESSION_DIR/summary.txt"
echo "  $SESSION_DIR/summary.md"
echo "  $SESSION_DIR/summary.json"
echo
