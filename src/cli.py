"""
amp-fw-sync CLI — diagnostic and inspection commands.

Usage:
  python src/cli.py query-amp
  python src/cli.py query-fw
  python src/cli.py list-instances
  python src/cli.py sync-now
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


def _make_reconciler(cfg: dict):
    from reconciler import Reconciler
    docker_cfg = cfg.get("docker", {})
    inspector = DockerInspector(
        socket_url=docker_cfg.get("socket", "unix:///var/run/docker.sock"),
        label_filter=docker_cfg.get("label_filter") or None,
    )
    fg_cfg = cfg["fortigate"]
    fg = FortigateClient(host=fg_cfg["host"], token=fg_cfg["token"], ssl_verify=fg_cfg.get("ssl_verify", True))
    amp = _make_amp(cfg)
    db_path = cfg.get("state_db_path", "/var/lib/amp-fw-sync/state.db")
    state = StateManager(db_path=db_path)
    from reconciler import Reconciler as _R
    host_ip = cfg.get("host_ip", "") or _R._detect_host_ip()
    reconciler = Reconciler(
        docker_inspector=inspector,
        state_manager=state,
        fortigate_client=fg,
        ext_ip=fg_cfg.get("ext_ip", ""),
        host_ip=host_ip,
        amp_client=amp,
    )
    return reconciler


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
    """List all AMP instances (running and stopped) with their configured ports."""
    amp = _make_amp(cfg)
    if not amp:
        print("AMP not configured.")
        return

    amp_instances = amp.get_instances()
    if not amp_instances:
        print("No AMP instances found (or login failed).")
        return

    # Build a name→status map from Docker for running indicator
    docker_cfg = cfg.get("docker", {})
    inspector = DockerInspector(
        socket_url=docker_cfg.get("socket", "unix:///var/run/docker.sock"),
        label_filter=docker_cfg.get("label_filter") or None,
    )
    docker_containers = {c["name"]: c["status"] for c in inspector.get_all_containers()}

    print(f"{'AMP INSTANCE':<30} {'STATUS':<10} {'PORTS'}")
    print("-" * 75)
    for name, info in sorted(amp_instances.items()):
        docker_name = f"AMP_{name}"
        docker_status = docker_containers.get(docker_name, "not running")
        ports_str = ", ".join(f"{p['host_port']}/{p['protocol']}" for p in info["ports"]) or "(none)"
        print(f"{name:<30} {docker_status:<10} {ports_str}")


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
    """List AMP instances alongside their expected firewall rule names and policy IDs."""
    amp = _make_amp(cfg)
    amp_instances = amp.get_instances() if amp else {}

    db_path = cfg.get("state_db_path", "/var/lib/amp-fw-sync/state.db")
    state: dict = {}
    if Path(db_path).exists():
        sm = StateManager(db_path=db_path)
        state = sm.load_all()

    docker_cfg = cfg.get("docker", {})
    inspector = DockerInspector(
        socket_url=docker_cfg.get("socket", "unix:///var/run/docker.sock"),
        label_filter=docker_cfg.get("label_filter") or None,
    )
    running_set = {c["name"] for c in inspector.get_all_containers() if c["status"] == "running"}

    print(f"\n{'AMP INSTANCE':<32} {'PORT':<8} {'PROTO':<6} {'VIP / RULE NAME':<50} {'POLICY ID'}")
    print("-" * 110)
    for instance_name, info in sorted(amp_instances.items()):
        saved = state.get(instance_name, {})
        policy_ids = saved.get("policy_ids", [])
        running = f"AMP_{instance_name}" in running_set

        if not info["ports"]:
            status = "running" if running else "stopped"
            print(f"{instance_name:<32} {'—':<8} {'—':<6} {'(no ports)':<50} ({status})")
            continue

        for i, p in enumerate(info["ports"]):
            rule_name = _obj_name(instance_name, p["host_port"], p["protocol"])
            pid = str(policy_ids[i]) if i < len(policy_ids) else "?"
            prefix = instance_name if i == 0 else ""
            print(f"{prefix:<32} {p['host_port']:<8} {p['protocol']:<6} {rule_name:<50} {pid}")
    print()


# ---------------------------------------------------------------------------
# Dry run
# ---------------------------------------------------------------------------

def cmd_dry_run(cfg: dict):
    """Show what FortiGate rules would be created/deleted without making changes."""
    amp = _make_amp(cfg)
    amp_instances = amp.get_instances() if amp else {}

    docker_cfg = cfg.get("docker", {})
    inspector = DockerInspector(
        socket_url=docker_cfg.get("socket", "unix:///var/run/docker.sock"),
        label_filter=docker_cfg.get("label_filter") or None,
    )
    running_set = {c["name"] for c in inspector.get_all_containers() if c["status"] == "running"}

    fg = _make_fg(cfg)
    fg_cfg = cfg["fortigate"]
    ext_ip = fg_cfg.get("ext_ip", "<ext_ip>")
    host_ip = cfg.get("host_ip", "") or "<auto-detected>"

    # Build expected rules from ALL AMP instances
    expected: list[dict] = []
    for instance_name, info in amp_instances.items():
        running = f"AMP_{instance_name}" in running_set
        for p in info["ports"]:
            name = _obj_name(instance_name, p["host_port"], p["protocol"])
            expected.append({"name": name, "port": p["host_port"], "proto": p["protocol"], "running": running})

    # Fetch existing amp-sync rules from FortiGate
    try:
        live_vip_names = {v["name"] for v in fg.get_managed_vips()}
        live_svc_names = {s["name"] for s in fg.get_managed_service_objects()}
        live_policies = {p["name"]: p for p in fg.get_managed_policies()}
        fw_reachable = True
    except Exception as e:
        print(f"WARNING: Could not reach FortiGate ({e}) — showing all rules as NEW\n")
        live_vip_names = live_svc_names = set()
        live_policies = {}
        fw_reachable = False

    expected_names = {r["name"] for r in expected}
    to_delete = live_vip_names - expected_names

    print(f"\next_ip : {ext_ip}")
    print(f"host_ip: {host_ip}")
    print(f"\n{'ACTION':<8} {'STATUS':<8} {'TYPE':<16} {'NAME'}")
    print("-" * 95)

    for r in sorted(expected, key=lambda x: x["name"]):
        desired_status = "enable" if r["running"] else "disable"
        exists_vip = r["name"] in live_vip_names
        exists_svc = r["name"] in live_svc_names
        exists_pol = r["name"] in live_policies

        vip_action  = "exists" if exists_vip else "CREATE"
        svc_action  = "exists" if exists_svc else "CREATE"
        if exists_pol:
            current_status = live_policies[r["name"]].get("status", "enable")
            pol_action = "UPDATE" if current_status != desired_status else "exists"
        else:
            pol_action = "CREATE"

        vip_label = f"VIP  ({ext_ip}:{r['port']} → {host_ip}:{r['port']} {r['proto'].upper()})"
        svc_label = f"Service Object  (port {r['port']}/{r['proto']})"
        pol_label = f"Policy"

        print(f"{vip_action:<8} {desired_status:<8} {vip_label:<55} {r['name']}")
        print(f"{svc_action:<8} {'':<8} {svc_label:<55} {r['name']}")
        print(f"{pol_action:<8} {'':<8} {pol_label:<55} {r['name']}")
        print()

    if to_delete:
        for name in sorted(to_delete):
            print(f"{'DELETE':<8} {'—':<8} {'VIP + Service + Policy':<55} {name}")
        print()

    if not fw_reachable:
        return
    creates = sum(1 for r in expected if r["name"] not in live_vip_names)
    updates = sum(1 for r in expected
                  if r["name"] in live_policies
                  and live_policies[r["name"]].get("status") != ("enable" if r["running"] else "disable"))
    deletes = len(to_delete)
    exists = len(expected) - creates - updates
    print(f"Summary: {creates} to create, {updates} to update status, {deletes} to delete, {exists} unchanged")


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


def cmd_sync_now(cfg: dict):
    """Trigger an immediate reconcile, bypassing the poll interval."""
    flag = _sync_flag_path(cfg)
    if not flag.exists():
        print("WARNING: Sync is currently DISABLED. Running a one-off reconcile anyway.")

    # Try the running service first for minimal disruption
    try:
        r = _requests.post("http://localhost:8000/sync/now", timeout=10)
        if r.ok:
            data = r.json()
            stats = data.get("stats", {})
            print(f"Reconcile complete: +{stats.get('added', 0)} added, -{stats.get('removed', 0)} removed, {stats.get('errors', 0)} errors")
            return
    except Exception:
        pass

    # Service not running — run reconcile directly
    print("Service not running; reconciling directly...")
    reconciler = _make_reconciler(cfg)
    stats = reconciler.reconcile()
    print(f"Reconcile complete: +{stats.get('added', 0)} added, -{stats.get('removed', 0)} removed, {stats.get('errors', 0)} errors")


def cmd_debug_amp(cfg: dict):
    """Dump raw ApplicationEndpoints from AMP for each instance."""
    amp_cfg = cfg.get("amp", {})
    if not (amp_cfg.get("host") and amp_cfg.get("username") and amp_cfg.get("password")):
        print("AMP not configured.")
        return

    from amp_client import AMPClient
    client = AMPClient(
        host=amp_cfg["host"],
        username=amp_cfg["username"],
        password=amp_cfg["password"],
    )

    data = client._post("/API/ADSModule/GetInstances")
    if data is None:
        print("No response from AMP (login failed?).")
        return

    entries = data if isinstance(data, list) else data.get("result", [])
    for entry in entries:
        for instance in entry.get("AvailableInstances", []):
            name = instance.get("InstanceName", "?")
            module = instance.get("ModuleName", "?")
            friendly = instance.get("FriendlyName", "")
            running = instance.get("Running", False)
            endpoints = instance.get("ApplicationEndpoints", [])

            print(f"\n{'='*60}")
            print(f"  InstanceName : {name}")
            print(f"  ModuleName   : {module}")
            print(f"  FriendlyName : {friendly}")
            print(f"  Running      : {running}")
            print(f"  Endpoints ({len(endpoints)}):")
            if endpoints:
                for ep in endpoints:
                    print(f"    DisplayName={ep.get('DisplayName')!r:30s}  Endpoint={ep.get('Endpoint')!r}")
            else:
                print("    (none)")
    print()


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
    sub.add_parser("query-fw",       help="List firewall rules created by this script (amp-sync- prefix)")
    sub.add_parser("list-instances", help="List AMP instances alongside their expected rule names")
    sub.add_parser("dry-run",        help="Show what rules would be created/deleted without making changes")
    sub.add_parser("sync-now",       help="Trigger an immediate reconcile (bypasses poll interval)")
    sub.add_parser("enable-sync",    help="Enable firewall sync (creates flag file, triggers immediate reconcile)")
    sub.add_parser("disable-sync",   help="Disable firewall sync (removes flag file, no further FW changes)")
    sub.add_parser("debug-amp",      help="Dump raw AMP ApplicationEndpoints for each instance")

    args = parser.parse_args()
    cfg = _load_config()

    dispatch = {
        "query-amp":      cmd_query_amp,
        "query-fw":       cmd_query_fw,
        "list-instances": cmd_list_instances,
        "dry-run":        cmd_dry_run,
        "sync-now":       cmd_sync_now,
        "enable-sync":    cmd_enable_sync,
        "disable-sync":   cmd_disable_sync,
        "debug-amp":      cmd_debug_amp,
    }
    dispatch[args.command](cfg)


if __name__ == "__main__":
    main()
