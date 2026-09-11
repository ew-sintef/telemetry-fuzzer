#!/usr/bin/env bash
set -euo pipefail

# ---------------- config ----------------

IMAGE_NAME="${IMAGE_NAME:-fuzz-lab}"
OUT_ROOT="${OUT_ROOT:-out}"

# ------------- helper funcs ------------

usage() {
cat <<EOF
Usage: $0 <service>

Services:
  http
  dns
  ssh
  sip
  iperf

Environment variables:
  IMAGE_NAME   Docker image name (default: fuzz-lab)
  OUT_ROOT     Output root directory (default: out)
EOF
}

# Resolve repo root

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# Optional configuration file

CONFIG_FILE="$REPO_ROOT/config/targets.env"

if [[ -f "$CONFIG_FILE" ]]; then
    # shellcheck disable=SC1090
    source "$CONFIG_FILE"
fi

service="${1:-}"

if [[ -z "$service" ]]; then
    usage
    exit 1
fi

script=""
default_port=""

case "$service" in

    http)
        script="fuzzing_scripts/services/http_fuzz.py"
        default_port="${DEFAULT_HTTP_PORT:-80}"
        default_ip="${DEFAULT_TARGET_IP:-127.0.0.1}"
        ;;

    dns)
        script="fuzzing_scripts/services/dns_fuzz.py"
        default_port="${DEFAULT_DNS_PORT:-53}"
        default_ip="${DEFAULT_TARGET_IP:-127.0.0.1}"
        ;;

    ssh)
        script="fuzzing_scripts/services/ssh_fuzz.py"
        default_port="${DEFAULT_SSH_PORT:-22}"
        default_ip="${DEFAULT_TARGET_IP:-127.0.0.1}"
        ;;

    sip)
        script="fuzzing_scripts/services/sip_fuzz.py"
        default_port="${DEFAULT_SIP_PORT:-5060}"
        default_ip="${DEFAULT_TARGET_IP:-127.0.0.1}"
        ;;

    iperf)
        script="fuzzing_scripts/services/iperf_fuzz.py"
        default_port="${DEFAULT_IPERF_PORT:-5201}"
        default_ip="${DEFAULT_TARGET_IP:-127.0.0.1}"
        ;;

    *)
        echo "Unknown service: $service"
        usage
        exit 1
        ;;
esac

read -rp "Target IP [$default_ip]: " ip
ip=${ip:-$default_ip}

read -rp "Target port [$default_port]: " port
port=${port:-$default_port}

base_dir="$REPO_ROOT/$OUT_ROOT/$service"

ts="$(date +%Y%m%d-%H%M%S)"

read -rp "Run label (folder name under $base_dir) [$ts]: " label
label=${label:-$ts}

host_dir="$base_dir/$label"

mkdir -p "$host_dir"

cat > "$host_dir/session_metadata.json" <<EOF
{
  "protocol": "$service",
  "target_ip": "$ip",
  "target_port": $port,
  "session_label": "$label",
  "created": "$(date -Is)"
}
EOF

container_name="fuzz-$service-$ts"

echo
echo "Starting $service fuzzing session"
echo "Target: $ip:$port"
echo "Output directory:"
echo "  $host_dir"
echo

container_id=$(
docker run -d \
    --net=host \
    --cap-add NET_ADMIN \
    --cap-add NET_RAW \
    --name "$container_name" \
    -v "$host_dir":/logs \
    -v "$REPO_ROOT":/repo:ro \
    -e LOG_DIR=/logs \
    -e TARGET_IP="$ip" \
    -e TARGET_PORT="$port" \
    -e SCRIPT_PATH="/repo/$script" \
    -e TCPDUMP_INTERFACE="${TCPDUMP_INTERFACE:-ens4}" \
    "$IMAGE_NAME"
)

echo "Container started."
echo
echo "Container name:"
echo "  $container_name"
echo
echo "Monitor progress with:"
echo "  docker logs -f $container_name"
echo
echo "Recent output:"
echo "  docker logs --tail 200 $container_name"
echo

# Background watcher
(
    echo "Waiting for container completion..." \
        > "$host_dir/summary_generation.log"

    exit_code=$(docker wait "$container_id")

    {
        echo
        echo "Container exited with code: $exit_code"
        echo "Generating summary..."
    } >> "$host_dir/summary_generation.log"

    python3 -B "$REPO_ROOT/fuzzing_scripts/analysis/generate_summary.py" \
        --session "$host_dir" \
        >> "$host_dir/summary_generation.log" 2>&1

    {
        echo
        echo "Summary generated:"
        echo "  $host_dir/summary.md"
    } >> "$host_dir/summary_generation.log"

) &

echo "Summary will be generated automatically when fuzzing completes."
echo
echo "Summary generation log:"
echo "  $host_dir/summary_generation.log"
echo
echo "Session directory:"
echo "  $host_dir"
