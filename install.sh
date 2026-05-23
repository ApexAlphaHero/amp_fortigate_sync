#!/usr/bin/env bash
# install.sh — install amp-fw-sync on Debian (Forky/Trixie/Bookworm)
# Requires Docker to already be installed.
# Run as root: sudo bash install.sh
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SERVICE_USER="amp-sync"
SECRETS_FILE="/etc/amp-fw-sync/secrets.env"

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

if ! command -v docker &>/dev/null; then
  echo "ERROR: Docker is not installed. Please install Docker first." >&2
  exit 1
fi

echo "==> Docker: $(docker --version)"

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
  sqlite3

# ---------------------------------------------------------------------------
# Service user → docker group (needs socket access)
# ---------------------------------------------------------------------------

echo "==> Creating system user '${SERVICE_USER}' (if absent)..."
id -u "${SERVICE_USER}" &>/dev/null || \
  useradd --system --no-create-home --shell /usr/sbin/nologin "${SERVICE_USER}"

echo "==> Adding '${SERVICE_USER}' to the docker group..."
usermod -aG docker "${SERVICE_USER}"

# ---------------------------------------------------------------------------
# Pre-populate secrets file if it doesn't exist yet
# ---------------------------------------------------------------------------

if [[ ! -f "${SECRETS_FILE}" ]]; then
  mkdir -p "$(dirname "${SECRETS_FILE}")"
  cat > "${SECRETS_FILE}" <<'EOF'
AMP_USERNAME=
AMP_PASSWORD=
FORTIGATE_API_TOKEN=
EOF
  chmod 600 "${SECRETS_FILE}"
  chown root:root "${SECRETS_FILE}"
  echo "==> Created ${SECRETS_FILE} — please fill in your credentials."
else
  echo "==> ${SECRETS_FILE} already exists, leaving it unchanged."
fi

echo ""
echo "----------------------------------------------------------------------"
echo " Fill in your credentials now:"
echo "   nano ${SECRETS_FILE}"
echo ""
echo " Then press Enter to continue the install."
echo "----------------------------------------------------------------------"
read -r -p ""

# ---------------------------------------------------------------------------
# Run the deploy script
# ---------------------------------------------------------------------------

echo "==> Running deploy.sh..."
bash "${SCRIPT_DIR}/deploy.sh"
