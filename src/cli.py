"""
amp-fw-sync CLI — diagnostic and inspection commands.

Usage:
  python src/cli.py query-amp
  python src/cli.py query-fw
  python src/cli.py list-instances
  python src/cli.py enable-sync
  python src/cli.py disable-sync
"""
import argparse
import json
import os
import sys
from pathlib import Path

import requests as _requests

import yaml
from dotenv import load_dotenv

sys.path.insert(0, str(Path(__file__).parent))

from amp_client import AMPClient
from docker_inspector import DockerInspector
from fortigate_client import FortigateClient
from reconciler import _obj_name, _safe_name
from state_manager import StateManager


# ---------------------------------------------------------------------------
# Config helpers
# ---------------------------------------------------------------------------

_SECRETS_PATHS = [
    Path("/etc/amp-fw-sync/secrets.env"),          # production
    Path(__file__).parent.parent / ".env",          # local dev
]


def _load_config() -> dict:
    for p in _SECRETS_PATHS:
        if p.exists():
            load_dotenv(p)
            break

    config_path = Path("/opt/amp-fw-sync/config.yaml")
    if not config_path.exists():
        config_path = Path(__file__).parent.parent / "config.yaml"

    with open(config_path) as f:
        cfg = yaml.safe_load(f)
    cfg.setdefault("amp", {})["username"] = os.environ.get("AMP_USERNAME", cfg["amp"].get("username", ""))
    cfg["amp"]["password"] = os.environ.get("AMP_PASSWORD", cfg["amp"].get("password", ""))
    cfg.setdefault("fortigate", {})["token"] = os.environ.get("FORTIGATE_API_TOKEN", cfg["fortigate"].get("token", ""))
    return cfg


def _make_fg(cfg: dict) -> FortigateClient:
    fg_cfg = cfg["fortigate"]
    return FortigateClient(
        host=fg_cfg["host"],
        token=fg_cfg["token"],
        ssl_verify=fg_cfg.get("ssl_verify", True),
    )


def _make_amp(cfg: dict):
    amp_cfg = cfg.get("amp", {})
    if amp_cfg.get("host") and amp_cfg.get("username") and amp_cfg.get("password"):
        return AMPClient(host=amp_cfg["host"], username=amp_cfg["username"], password=amp_cfg["password"])
    return None


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------

def cmd_query_amp(cfg: dict):
    """Query AMP + Docker and print each instance with its exposed ports."""
    docker_cfg = cfg.get("docker", {})
    inspector = DockerInspector(
        socket_url=docker_cfg.get("socket", "unix:///var/run/docker.sock"),
        label_filter=docker_cfg.get("label_filter") or None,
    )
    amp = _make_amp(cfg)
    amp_instances = amp.get_instances() if amp else {}

    containers = inspector.get_running_containers()
    if not containers:
        print("No running containers found.")
        return

    print(f"{'CONTAINER':<30} {'AMP INSTANCE':<30} {'PORTS':<25} {'SOURCE'}")
    print("-" * 95)
    for c in containers:
        amp_label = amp.resolve_container_name(c["name"], amp_instances) if amp else c["name"]

        amp_ports = amp_instances.get(amp_label, {}).get("ports", []) if amp else []
        docker_ports = c["ports"]

        if amp_ports:
            ports_str = ", ".join(f"{p['host_port']}/{p['protocol']}" for p in amp_ports)
            source = "amp"
        elif docker_ports:
            ports_str = ", ".join(f"{p['host_port']}/{p['protocol']}" for p in docker_ports)
            source = "docker"
        else:
            ports_str = "(none)"
            source = ""

        print(f"{c['name']:<30} {amp_label:<30} {ports_str:<25} {source}")

    if not amp:
        print("\n(AMP not configured — showing Docker container names only)")


def cmd_query_fw(cfg: dict):
    """List all firewall rules created by this script (tagged [amp-sync])."""
    fg = _make_fg(cfg)

    vips = fg.get_managed_vips()
    services = fg.get_managed_service_objects()
    policies = fg.get_managed_policies()

    print(f"\n=== Virtual IPs ({len(vips)}) ===")
    if vips:
        print(f"  {'NAME':<45} {'EXT IP':<16} {'EXT PORT':<10} {'MAPPED IP':<16} {'PROTO'}")
        print("  " + "-" * 95)
        for v in vips:
            mapped = (v.get("mappedip") or [{}])[0].get("range", "?")
            print(f"  {v['name']:<45} {v.get('extip','?'):<16} {v.get('extport','?'):<10} {mapped:<16} {v.get('protocol','?')}")
    else:
        print("  (none)")

    print(f"\n=== Service Objects ({len(services)}) ===")
    if services:
        print(f"  {'NAME':<45} {'TCP RANGE':<15} {'UDP RANGE'}")
        print("  " + "-" * 75)
        for s in services:
            print(f"  {s['name']:<45} {s.get('tcp-portrange',''):<15} {s.get('udp-portrange','')}")
    else:
        print("  (none)")

    print(f"\n=== Policies ({len(policies)}) ===")
    if policies:
        print(f"  {'ID':<8} {'NAME':<45} {'STATUS'}")
        print("  " + "-" * 60)
        for p in policies:
            pid = p.get("policyid") or p.get("id", "?")
            print(f"  {str(pid):<8} {p['name']:<45} {p.get('status','?')}")
    else:
        print("  (none)")
    print()


def cmd_list_instances(cfg: dict):
    """List AMP instances alongside their expected firewall rule names."""
    docker_cfg = cfg.get("docker", {})
    inspector = DockerInspector(
        socket_url=docker_cfg.get("socket", "unix:///var/run/docker.sock"),
        label_filter=docker_cfg.get("label_filter") or None,
    )
    amp = _make_amp(cfg)
    amp_instances = amp.get_instances() if amp else {}

    # Also load SQLite state for policy IDs
    db_path = cfg.get("state_db_path", "/var/lib/amp-fw-sync/state.db")
    state: dict = {}
    if Path(db_path).exists():
        sm = StateManager(db_path=db_path)
        state = sm.load_all()
    state_by_name = {v["name"]: v for v in state.values()}

    containers = inspector.get_running_containers()
    if not containers:
        print("No running containers found.")
        return

    print(f"\n{'AMP INSTANCE / CONTAINER':<32} {'PORT':<8} {'PROTO':<6} {'VIP / RULE NAME':<50} {'POLICY ID'}")
    print("-" * 110)
    for c in containers:
        label = amp.resolve_container_name(c["name"], amp_instances) if amp else c["name"]
        saved = state_by_name.get(label, {})
        policy_ids = saved.get("policy_ids", [])

        if not c["ports"]:
            print(f"{label:<32} {'—':<8} {'—':<6} {'(no exposed ports)'}")
            continue

        for i, p in enumerate(c["ports"]):
            rule_name = _obj_name(label, p["host_port"], p["protocol"])
            pid = str(policy_ids[i]) if i < len(policy_ids) else "?"
            prefix = label if i == 0 else ""
            print(f"{prefix:<32} {p['host_port']:<8} {p['protocol']:<6} {rule_name:<50} {pid}")
    print()


# ---------------------------------------------------------------------------
# Sync control
# ---------------------------------------------------------------------------

def _sync_flag_path(cfg: dict) -> Path:
    db_path = cfg.get("state_db_path", "/var/lib/amp-fw-sync/state.db")
    return Path(db_path).parent / "sync_enabled"


def _notify_service(endpoint: str):
    """Best-effort POST to the running service; silently ignored if not running."""
    try:
        _requests.post(f"http://localhost:8000{endpoint}", timeout=3)
    except Exception:
        pass


def cmd_enable_sync(cfg: dict):
    flag = _sync_flag_path(cfg)
    flag.parent.mkdir(parents=True, exist_ok=True)
    flag.touch()
    print("Sync ENABLED.")
    _notify_service("/sync/enable")
    print("Service will reconcile immediately (if running) or on next poll cycle.")


def cmd_disable_sync(cfg: dict):
    flag = _sync_flag_path(cfg)
    flag.unlink(missing_ok=True)
    print("Sync DISABLED. No further firewall changes will be made.")
    _notify_service("/sync/disable")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        prog="amp-fw-sync",
        description="Diagnostic commands for amp-fw-sync",
    )
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("query-amp",      help="List AMP instances and their Docker container ports")
    sub.add_parser("query-fw",       help="List firewall rules created by this script ([amp-sync] tagged)")
    sub.add_parser("list-instances", help="List AMP instances alongside their expected rule names")
    sub.add_parser("enable-sync",    help="Enable firewall sync (creates flag file, triggers immediate reconcile)")
    sub.add_parser("disable-sync",   help="Disable firewall sync (removes flag file, no further FW changes)")

    args = parser.parse_args()
    cfg = _load_config()

    dispatch = {
        "query-amp":      cmd_query_amp,
        "query-fw":       cmd_query_fw,
        "list-instances": cmd_list_instances,
        "enable-sync":    cmd_enable_sync,
        "disable-sync":   cmd_disable_sync,
    }
    dispatch[args.command](cfg)


if __name__ == "__main__":
    main()
