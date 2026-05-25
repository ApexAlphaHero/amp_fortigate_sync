# amp-fw-sync

Watches [CubeCoders AMP](https://cubecoders.com/AMP) game server instances and automatically syncs their port bindings to FortiGate firewall rules. When an AMP instance is configured with ports, the script creates the matching FortiGate objects. When ports change or an instance is removed, the rules are updated or deleted.

## How it works

For each AMP instance, three FortiGate objects are created and kept in sync:

| Object | Name pattern | Purpose |
|--------|-------------|---------|
| Virtual IP (one per port group) | `amp-sync-{instance}-{port}-{proto}` | DNAT — maps `ext_ip:port` → `host_ip:port` |
| Service object (one per instance) | `amp-sync-{instance}` | Defines all ports/protocols for this instance |
| Policy (one per instance) | `amp-sync-{instance}` | Allows traffic through the firewall |

Consecutive ports of the same protocol are grouped into a single VIP range (e.g. ports 7777–7779 UDP become one VIP). All objects are prefixed `amp-sync-` — the script only ever touches objects it created.

Instances that are stopped have their policy set to `disabled` rather than deleted, so the rules are ready when the server starts again.

## Installation (Debian / Ubuntu)

```bash
sudo apt-get install -y git
git clone https://github.com/ApexAlphaHero/amp_fortigate_sync.git
cd amp_fortigate_sync
sudo bash deploy.sh
```

The deploy script creates the `amp-sync` system user, sets up a Python venv, copies source files to `/opt/amp-fw-sync/`, installs the systemd service, and creates `/etc/amp-fw-sync/secrets.env` for credentials.

**The service starts with sync disabled.** Fill in credentials, configure `config.yaml`, verify things look right with `query-amp` and `dry-run`, then enable sync when ready.

### Updating

```bash
cd amp_fortigate_sync
git pull
sudo bash deploy.sh
```

`deploy.sh` preserves your existing `/opt/amp-fw-sync/config.yaml` if you've modified it.

### Installed paths

| Path | Contents |
|------|----------|
| `/opt/amp-fw-sync/src/` | Source files |
| `/opt/amp-fw-sync/venv/` | Python virtualenv |
| `/opt/amp-fw-sync/config.yaml` | Configuration |
| `/var/lib/amp-fw-sync/state.db` | SQLite state database |
| `/var/lib/amp-fw-sync/sync_enabled` | Flag file — exists when sync is on |
| `/etc/amp-fw-sync/secrets.env` | Credentials (never commit this) |
| `/etc/systemd/system/amp-fw-sync.service` | Systemd unit |

## Configuration

Edit `/opt/amp-fw-sync/config.yaml`. Credentials go in `/etc/amp-fw-sync/secrets.env` — never in the config file.

```yaml
docker:
  socket: "unix:///var/run/docker.sock"
  label_filter: ""          # e.g. "amp-sync=true" — blank = watch all containers

amp:
  host: "http://192.168.1.100:8080"   # Use the LAN IP — AMP blocks auth from 127.0.0.1
  excluded_instances: ["ADS01"]       # AMP manager instance to skip

fortigate:
  host: "https://192.168.1.1"         # FortiGate management IP or hostname
  ext_ip: "203.0.113.1"               # WAN/public IP used as VIP external address
  vdom: "root"                        # VDOM name — set to null if VDOMs are disabled
  ssl_verify: true                    # Set false for self-signed certs
  dstintf: "any"                      # Destination interface for created policies
  srcaddr: ["all"]                    # Source address objects for created policies
  ssl_ssh_profile: null               # SSL/SSH inspection profile (null to disable)
  policy_insert_after: null           # Policy ID to insert new rules after (null = default)
  service_category: "amp-sync"        # Service category for created service objects (null = none)

poll_interval_seconds: 300
log_level: "INFO"
state_db_path: "/var/lib/amp-fw-sync/state.db"

# host_ip: auto-detected from the default network route.
# Override if auto-detection picks the wrong interface.
# host_ip: "192.168.1.100"
```

### Secrets file

`/etc/amp-fw-sync/secrets.env`:

```env
AMP_USERNAME=your-amp-username
AMP_PASSWORD=your-amp-password
FORTIGATE_API_TOKEN=your-fortigate-api-token
```

The FortiGate API token is created under **System > Administrators > Create New > REST API Admin**. The AMP credentials are a local AMP user account — use the server's LAN IP for `amp.host`, not `localhost`.

## CLI commands

All commands use the venv Python:

```bash
PYTHON=/opt/amp-fw-sync/venv/bin/python
CLI=/opt/amp-fw-sync/src/cli.py
```

| Command | Description |
|---------|-------------|
| `$PYTHON $CLI query-amp` | List all AMP instances, their running status, and configured ports |
| `$PYTHON $CLI query-fw` | List all `amp-sync-*` objects currently on the FortiGate |
| `$PYTHON $CLI list-instances` | Show each instance alongside its expected rule names and policy ID |
| `$PYTHON $CLI dry-run` | Preview what would be created/updated/deleted without making changes |
| `$PYTHON $CLI sync-now` | Trigger an immediate reconcile (bypasses poll interval) |
| `$PYTHON $CLI enable-sync` | Enable firewall sync and trigger an immediate reconcile |
| `$PYTHON $CLI disable-sync` | Disable firewall sync (no further firewall changes) |
| `$PYTHON $CLI debug-amp` | Dump raw AMP network info for each instance |

## Sync enable / disable

The service starts with sync **disabled**. Nothing is written to the firewall until you explicitly enable it.

```bash
# Enable — starts syncing immediately
sudo /opt/amp-fw-sync/venv/bin/python /opt/amp-fw-sync/src/cli.py enable-sync

# Disable — stops all future sync (existing rules are left in place)
sudo /opt/amp-fw-sync/venv/bin/python /opt/amp-fw-sync/src/cli.py disable-sync
```

## Health and status

The service exposes a small HTTP API on port 8000:

```bash
curl http://localhost:8000/health    # {"status": "ok"}
curl http://localhost:8000/status    # last reconcile time, container count, sync state
curl -X POST http://localhost:8000/sync/now     # trigger reconcile
curl -X POST http://localhost:8000/sync/enable  # enable sync
curl -X POST http://localhost:8000/sync/disable # disable sync
```

## Service management

```bash
systemctl status amp-fw-sync
systemctl restart amp-fw-sync
journalctl -u amp-fw-sync -f        # follow logs
```

## Local development

```bash
cp .env.example .env
# Fill in AMP_USERNAME, AMP_PASSWORD, FORTIGATE_API_TOKEN

python -m venv venv
source venv/bin/activate    # Windows: venv\Scripts\activate
pip install -r requirements.txt

python src/main.py
```
