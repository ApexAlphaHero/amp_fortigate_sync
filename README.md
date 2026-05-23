# amp-fw-sync

Automatically syncs Docker container port bindings to FortiGate firewall address objects and policies.

When a container starts with exposed ports, `amp-fw-sync` creates matching FortiGate address objects and policy rules tagged `[amp-sync]`. When the container stops, those rules are removed. AMP (CubeCoders) instance names are used as labels where available.

## Requirements

- Python 3.11+
- Docker socket access
- FortiGate with REST API enabled

## Quick Start

```bash
cp .env.example .env
# Edit .env with your tokens
# Edit config.yaml with your FortiGate host and interfaces

python -m venv venv
source venv/bin/activate   # Windows: venv\Scripts\activate
pip install -r requirements.txt

python src/main.py
```

Health check: `curl http://localhost:8000/health`
Status: `curl http://localhost:8000/status`

## Configuration

All settings live in `config.yaml`. Secrets (`AMP_API_TOKEN`, `FORTIGATE_API_TOKEN`) are loaded from `.env` or the environment.

| Key | Description |
|-----|-------------|
| `docker.socket` | Docker socket path |
| `docker.label_filter` | Only watch containers with this label (blank = all) |
| `fortigate.host` | FortiGate base URL |
| `fortigate.interfaces` | Interfaces for created policies |
| `fortigate.ssl_verify` | Verify FortiGate TLS cert |
| `poll_interval_seconds` | Fallback reconcile interval |

## Deployment

```bash
sudo bash deploy.sh
```

See `systemd/amp-fw-sync.service` for the unit file.

## Tests

```bash
pytest tests/
```
