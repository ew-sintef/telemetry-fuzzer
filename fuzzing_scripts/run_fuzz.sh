#!/usr/bin/env bash
set -euo pipefail

# ---------------- config ----------------
IMAGE_NAME="${IMAGE_NAME:-fuzz-lab}"   # docker image to use
OUT_ROOT="${OUT_ROOT:-out}"           # base dir for run outputs (relative to repo root)

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

# Resolve repo root (one level up from this script)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# Optional: load defaults from config/targets.env if present
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
    ;;
  dns)
    script="fuzzing_scripts/services/dns_fuzz.py"
    default_port="${DEFAULT_DNS_PORT:-53}"
    ;;
  ssh)
    script="fuzzing_scripts/services/ssh_fuzz.py"
    default_port="${DEFAULT_SSH_PORT:-22}"
    ;;
  sip)
    script="fuzzing_scripts/services/sip_fuzz.py"
    default_port="${DEFAULT_SIP_PORT:-5060}"
    ;;
  iperf)
    script="fuzzing_scripts/services/iperf_fuzz.py"
    default_port="${DEFAULT_IPERF_PORT:-5001}"
    ;;
  *)
    echo "Unknown service: $service"
    usage
    exit 1
    ;;
esac

# Default IP from config file if set, otherwise 127.0.0.1
default_ip="${DEFAULT_TARGET_IP:-127.0.0.1}"

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

name="fuzz-$service-$ts"

echo "Starting $service fuzz as container: $name"
echo "  Target: $ip:$port"
echo "  Logs/output: $host_dir"
echo

docker run -d --net=host \
  --cap-add NET_ADMIN --cap-add NET_RAW \
  --name "$name" \
  -v "$host_dir":/logs \
  -v "$REPO_ROOT":/repo:ro \
  -e LOG_DIR=/logs \
  -e TARGET_IP="$ip" \
  -e TARGET_PORT="$port" \
  -e SCRIPT_PATH="/repo/$script" \
  -e TCPDUMP_INTERFACE="ens4" \
  "$IMAGE_NAME"

echo "Container started."
echo "Follow logs with:"
echo "  docker logs -f $name"
echo "Output dir on host:"
echo "  $host_dir"
