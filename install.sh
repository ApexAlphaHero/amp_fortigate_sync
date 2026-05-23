#!/usr/bin/env bash
# install.sh — full system install for amp-fw-sync on Debian (Forky/Trixie/Bookworm)
# Run as root: sudo bash install.sh
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SERVICE_USER="amp-sync"

# ---------------------------------------------------------------------------
# Guards
# ---------------------------------------------------------------------------

if [[ $EUID -ne 0 ]]; then
  echo "ERROR: Run as root: sudo bash install.sh" >&2
  exit 1
fi

if ! grep -qi "debian" /etc/os-release 2>/dev/null; then
  echo "ERROR: This script targets Debian. Detected OS:" >&2
  grep PRETTY_NAME /etc/os-release >&2
  exit 1
fi

# ---------------------------------------------------------------------------
# Detect codename (forky, trixie, bookworm, ...)
# ---------------------------------------------------------------------------

. /etc/os-release
DEBIAN_CODENAME="${VERSION_CODENAME:-}"
if [[ -z "${DEBIAN_CODENAME}" ]]; then
  DEBIAN_CODENAME="$(lsb_release -cs 2>/dev/null || echo bookworm)"
fi
echo "==> Detected Debian codename: ${DEBIAN_CODENAME}"

# ---------------------------------------------------------------------------
# System packages
# ---------------------------------------------------------------------------

echo "==> Updating apt..."
apt-get update -qq

echo "==> Installing system dependencies..."
apt-get install -y --no-install-recommends \
  python3 \
  python3-venv \
  python3-pip \
  curl \
  ca-certificates \
  gnupg \
  lsb-release \
  sqlite3

# ---------------------------------------------------------------------------
# Docker Engine (official Docker repo)
# ---------------------------------------------------------------------------

if command -v docker &>/dev/null; then
  echo "==> Docker already installed ($(docker --version)), skipping."
else
  echo "==> Adding Docker apt repository..."
  install -m 0755 -d /etc/apt/keyrings
  curl -fsSL https://download.docker.com/linux/debian/gpg \
    | gpg --dearmor -o /etc/apt/keyrings/docker.gpg
  chmod a+r /etc/apt/keyrings/docker.gpg

  # Docker may not yet publish a Forky repo; fall back to bookworm if needed.
  DOCKER_CODENAME="${DEBIAN_CODENAME}"
  DOCKER_REPO_URL="https://download.docker.com/linux/debian"
  if ! curl -fsSL --head \
      "${DOCKER_REPO_URL}/dists/${DOCKER_CODENAME}/Release" &>/dev/null; then
    echo "    Docker repo not yet available for '${DOCKER_CODENAME}', using 'bookworm'."
    DOCKER_CODENAME="bookworm"
  fi

  echo \
    "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] \
${DOCKER_REPO_URL} ${DOCKER_CODENAME} stable" \
    > /etc/apt/sources.list.d/docker.list

  apt-get update -qq
  apt-get install -y --no-install-recommends \
    docker-ce \
    docker-ce-cli \
    containerd.io \
    docker-buildx-plugin

  systemctl enable --now docker
  echo "==> Docker installed: $(docker --version)"
fi

# ---------------------------------------------------------------------------
# Service user → docker group (needs socket access)
# ---------------------------------------------------------------------------

echo "==> Creating system user '${SERVICE_USER}' (if absent)..."
id -u "${SERVICE_USER}" &>/dev/null || \
  useradd --system --no-create-home --shell /usr/sbin/nologin "${SERVICE_USER}"

echo "==> Adding '${SERVICE_USER}' to the docker group..."
usermod -aG docker "${SERVICE_USER}"

# ---------------------------------------------------------------------------
# Run the deploy script
# ---------------------------------------------------------------------------

echo ""
echo "==> Running deploy.sh..."
bash "${SCRIPT_DIR}/deploy.sh"
