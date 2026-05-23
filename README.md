# amp-fw-sync

Watches Docker containers and automatically syncs their port bindings to FortiGate firewall rules. When a container starts with exposed ports, the script creates a **Virtual IP** (port-forward DNAT), a **custom service object**, and a **policy** — all tagged `[amp-sync]` in their comments. When the container stops or is deleted, those rules are removed.

AMP (CubeCoders) instance names are used as human-readable labels where available, falling back to Docker container names.

## How it works

For each exposed container port, three FortiGate objects are created:

| Object | Name pattern | Purpose |
|--------|-------------|---------|
| Virtual IP | `amp-sync-{label}-{port}-{proto}` | DNAT — maps FortiGate WAN IP:port → host IP:port |
| Service object | `amp-sync-{label}-{port}-{proto}` | Defines the port/protocol |
| Policy | `amp-sync-{label}-{port}-{proto}` | Allows the traffic through |

The `[amp-sync]` comment tag is how the script identifies its own rules — it never touches anything it didn't create.

## Installation (Debian)

```bash
sudo apt-get install -y git
git clone https://github.com/ApexAlphaHero/amp_fortigate_sync.git
cd amp_fortigate_sync
sudo bash install.sh
```

The install script handles Python, Docker, the `amp-sync` system user, venv, and the systemd service. It will pause and prompt you to write secrets before starting.

Installs to:

| Path | Contents |
|------|----------|
| `/opt/amp-fw-sync/` | Source files and venv |
| `/var/lib/amp-fw-sync/state.db` | SQLite state |
| `/etc/amp-fw-sync/secrets.env` | Secrets (AMP credentials, FortiGate token) |
| `/etc/systemd/system/amp-fw-sync.service` | Systemd unit |

## Configuration

Edit `config.yaml` before installing:

| Key | Description |
|-----|-------------|
| `docker.socket` | Docker socket path |
| `docker.label_filter` | Only watch containers with this label (blank = all) |
| `amp.host` | AMP web UI base URL (e.g. `http://localhost:8080`) |
| `fortigate.host` | FortiGate base URL |
| `fortigate.ext_ip` | FortiGate WAN/external IP — used as the VIP external address |
| `fortigate.interfaces` | Source interfaces for created policies |
| `fortigate.ssl_verify` | Verify FortiGate TLS certificate |
| `poll_interval_seconds` | Fallback reconcile interval in seconds |

Secrets go in `/etc/amp-fw-sync/secrets.env` (or `.env` for local dev):

```env
AMP_USERNAME=your-amp-username
AMP_PASSWORD=your-amp-password
FORTIGATE_API_TOKEN=your-fortigate-token
```

## CLI commands

```bash
# What's running in AMP/Docker and what ports are exposed?
python src/cli.py query-amp

# What [amp-sync] rules currently exist on the firewall?
python src/cli.py query-fw

# Which AMP instance maps to which rule name and policy ID?
python src/cli.py list-instances
```

## Health and status

```bash
curl http://localhost:8000/health
curl http://localhost:8000/status
```

## Local development

```bash
cp .env.example .env
# Fill in AMP_USERNAME, AMP_PASSWORD, FORTIGATE_API_TOKEN

python -m venv venv
source venv/bin/activate   # Windows: venv\Scripts\activate
pip install -r requirements.txt

python src/main.py
```

## Tests

```bash
pytest tests/
```
