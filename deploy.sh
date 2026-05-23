#!/usr/bin/env bash
set -euo pipefail

INSTALL_DIR="/opt/amp-fw-sync"
VENV_DIR="${INSTALL_DIR}/venv"
STATE_DIR="/var/lib/amp-fw-sync"
SECRETS_FILE="/etc/amp-fw-sync/secrets.env"
SERVICE_NAME="amp-fw-sync"
SERVICE_USER="amp-sync"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [[ $EUID -ne 0 ]]; then
  echo "ERROR: This script must be run as root (sudo bash deploy.sh)" >&2
  exit 1
fi

echo "==> Creating system user '${SERVICE_USER}' (if absent)..."
id -u "${SERVICE_USER}" &>/dev/null || \
  useradd --system --no-create-home --shell /usr/sbin/nologin "${SERVICE_USER}"

echo "==> Creating directories..."
mkdir -p "${INSTALL_DIR}/src" "${STATE_DIR}" "$(dirname "${SECRETS_FILE}")"

echo "==> Creating Python venv at ${VENV_DIR}..."
python3 -m venv "${VENV_DIR}"
"${VENV_DIR}/bin/pip" install --quiet --upgrade pip
"${VENV_DIR}/bin/pip" install --quiet -r "${SCRIPT_DIR}/requirements.txt"

echo "==> Copying source files..."
cp -r "${SCRIPT_DIR}/src/." "${INSTALL_DIR}/src/"
cp "${SCRIPT_DIR}/config.yaml" "${INSTALL_DIR}/config.yaml"

echo "==> Installing systemd unit..."
cp "${SCRIPT_DIR}/systemd/${SERVICE_NAME}.service" "/etc/systemd/system/${SERVICE_NAME}.service"

echo "==> Setting ownership..."
chown -R "${SERVICE_USER}:${SERVICE_USER}" "${INSTALL_DIR}" "${STATE_DIR}"
chmod 750 "${INSTALL_DIR}" "${STATE_DIR}"

if [[ ! -f "${SECRETS_FILE}" ]]; then
  mkdir -p "$(dirname "${SECRETS_FILE}")"
  cat > "${SECRETS_FILE}" <<'EOF'
AMP_USERNAME=
AMP_PASSWORD=
FORTIGATE_API_TOKEN=
EOF
  echo "==> Created ${SECRETS_FILE} — fill in credentials before starting the service."
fi

chmod 600 "${SECRETS_FILE}"
chown "${SERVICE_USER}:${SERVICE_USER}" "${SECRETS_FILE}"

echo "==> Enabling and starting ${SERVICE_NAME}..."
systemctl daemon-reload
systemctl enable --now "${SERVICE_NAME}"

echo ""
echo "Done. Check status with:"
echo "  systemctl status ${SERVICE_NAME}"
echo "  journalctl -u ${SERVICE_NAME} -f"
echo "  curl http://localhost:8000/health"
