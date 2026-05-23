#!/usr/bin/env bash
# install.sh — install amp-fw-sync on Debian (Forky/Trixie/Bookworm)
# Requires Docker to already be installed.
# Run as root: sudo bash install.sh
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SERVICE_USER="amp-sync"
SERVICE_NAME="amp-fw-sync"
SECRETS_FILE="/etc/amp-fw-sync/secrets.env"
CONFIG_FILE="/opt/amp-fw-sync/config.yaml"

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
# Helper: check if a file has any non-empty variable value (VAR=something)
# ---------------------------------------------------------------------------
secrets_configured() {
  grep -qE '^[A-Za-z_]+=.+' "${SECRETS_FILE}" 2>/dev/null
}

# Helper: check if config.yaml has been changed from the repo default
config_modified() {
  [[ -f "${CONFIG_FILE}" ]] && ! diff -q "${SCRIPT_DIR}/config.yaml" "${CONFIG_FILE}" &>/dev/null
}

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
# Step 1 — Secrets
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
fi

if secrets_configured; then
  echo "==> secrets.env already configured, skipping editor."
else
  echo ""
  echo "======================================================================"
  echo " STEP 1 OF 2 — Secrets"
  echo " Fill in your AMP and FortiGate credentials, then save and close."
  echo "======================================================================"
  read -r -p "Press Enter to open secrets.env..."
  ${EDITOR:-vi} "${SECRETS_FILE}"
fi

# ---------------------------------------------------------------------------
# Check if config was modified before deploy may copy a fresh one
# ---------------------------------------------------------------------------

CONFIG_WAS_MODIFIED=$(config_modified && echo true || echo false)

# ---------------------------------------------------------------------------
# Deploy (copies src/, installs venv, registers systemd unit)
# ---------------------------------------------------------------------------

echo ""
echo "==> Running deploy.sh..."
bash "${SCRIPT_DIR}/deploy.sh"

# ---------------------------------------------------------------------------
# Step 2 — Config
# ---------------------------------------------------------------------------

if [[ "${CONFIG_WAS_MODIFIED}" == "true" ]]; then
  echo "==> config.yaml already configured, skipping editor."
else
  echo ""
  echo "======================================================================"
  echo " STEP 2 OF 2 — Configuration"
  echo " Set your FortiGate host, public IP, and AMP host, then save and close."
  echo "======================================================================"
  read -r -p "Press Enter to open config.yaml..."
  ${EDITOR:-vi} "${CONFIG_FILE}"
fi

# ---------------------------------------------------------------------------
# Restart service to pick up config
# ---------------------------------------------------------------------------

echo ""
echo "==> Restarting ${SERVICE_NAME}..."
systemctl restart "${SERVICE_NAME}"

echo ""
echo "======================================================================"
echo " Done! Useful commands:"
echo ""
echo "   systemctl status ${SERVICE_NAME}"
echo "   journalctl -u ${SERVICE_NAME} -f"
echo "   curl http://localhost:8000/health"
echo "   curl http://localhost:8000/status"
echo ""
echo "   # Diagnostic CLI:"
echo "   /opt/amp-fw-sync/venv/bin/python /opt/amp-fw-sync/src/cli.py query-amp"
echo "   /opt/amp-fw-sync/venv/bin/python /opt/amp-fw-sync/src/cli.py query-fw"
echo "   /opt/amp-fw-sync/venv/bin/python /opt/amp-fw-sync/src/cli.py list-instances"
echo "======================================================================"
