#!/usr/bin/env bash
# Install a recent version of Docker Engine on Ubuntu.
# Based on the official Docker docs:
# https://docs.docker.com/engine/install/ubuntu/

set -euo pipefail

# Use sudo if not running as root
if [ "$(id -u)" -eq 0 ]; then
    SUDO=""
else
    SUDO="sudo"
fi

if [ ! -r /etc/os-release ]; then
    echo "Cannot read /etc/os-release. Are you on a systemd/Ubuntu-like distro?"
    exit 1
fi

# shellcheck source=/dev/null
. /etc/os-release

# Accept Ubuntu and Ubuntu-like distros
if [[ "${ID:-}" != "ubuntu" && "${ID_LIKE:-}" != *"ubuntu"* ]]; then
    echo "This script only supports Ubuntu (or Ubuntu-like) systems. Detected: ${PRETTY_NAME:-unknown}"
    exit 1
fi

# If Docker already exists, bail out early
if command -v docker >/dev/null 2>&1; then
    echo "Docker already installed. Exiting..."
    exit 0
fi

echo "[+] Installing Docker Engine on ${PRETTY_NAME:-Ubuntu}..."

# Update package index and install prerequisites
$SUDO apt-get update
$SUDO apt-get install -y \
    ca-certificates \
    curl \
    gnupg \
    lsb-release

# Create keyring directory if needed
$SUDO install -m 0755 -d /etc/apt/keyrings

# Add Docker’s official GPG key (modern keyring method, no apt-key)
if [ ! -f /etc/apt/keyrings/docker.gpg ]; then
    echo "[+] Fetching Docker GPG key..."
    curl -fsSL https://download.docker.com/linux/ubuntu/gpg \
        | $SUDO gpg --dearmor -o /etc/apt/keyrings/docker.gpg
    $SUDO chmod a+r /etc/apt/keyrings/docker.gpg
fi

# Determine Ubuntu codename (e.g. jammy, noble)
UBUNTU_CODENAME="${UBUNTU_CODENAME:-${VERSION_CODENAME:-$(lsb_release -cs)}}"

# Add Docker APT repository with signed-by option
echo "[+] Adding Docker APT repository..."
echo \
"deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu \
$UBUNTU_CODENAME stable" | $SUDO tee /etc/apt/sources.list.d/docker.list >/dev/null

# Update package index and install Docker Engine + extras
echo "[+] Installing Docker packages..."
$SUDO apt-get update
$SUDO apt-get install -y \
    docker-ce \
    docker-ce-cli \
    containerd.io \
    docker-buildx-plugin \
    docker-compose-plugin

# Optionally add the calling user to the docker group for rootless use
TARGET_USER="${SUDO_USER:-$USER}"

if getent passwd "$TARGET_USER" >/dev/null 2>&1; then
    if ! getent group docker >/dev/null 2>&1; then
        $SUDO groupadd docker
    fi

    if ! id -nG "$TARGET_USER" | grep -qw docker; then
        echo "[+] Adding user '$TARGET_USER' to 'docker' group..."
        $SUDO usermod -aG docker "$TARGET_USER"
        echo "    -> Log out and back in (or reboot) for this to take effect."
    fi
fi

# Make sure Docker is running (ignore failure on weird minimal images)
$SUDO systemctl enable --now docker >/dev/null 2>&1 || true

echo "[+] Docker installation complete."
echo "    Test it with:"
echo "      docker run --rm hello-world"
