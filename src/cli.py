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
from reconciler import _obj_name, _safe_name, _group_consecutive_ports, _port_range_str, _policy_name
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
    fg = FortigateClient(host=fg_cfg["host"], token=fg_cfg["token"], ssl_verify=fg_cfg.get("ssl_verify", True), vdom=fg_cfg.get("vdom") or None)
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
    reconciler._ssl_ssh_profile = fg_cfg.get("ssl_ssh_profile") or None
    reconciler._policy_insert_after = fg_cfg.get("policy_insert_after") or None
    reconciler._service_category = fg_cfg.get("service_category") or None
    reconciler._dstintf = fg_cfg.get("dstintf") or "any"
    reconciler._srcaddr = fg_cfg.get("srcaddr") or ["all"]
    return reconciler


def _make_fg(cfg: dict) -> FortigateClient:
    fg_cfg = cfg["fortigate"]
    return FortigateClient(
        host=fg_cfg["host"],
        token=fg_cfg["token"],
        ssl_verify=fg_cfg.get("ssl_verify", True),
        vdom=fg_cfg.get("vdom") or None,
    )


def _make_amp(cfg: dict):
    amp_cfg = cfg.get("amp", {})
    if amp_cfg.get("host") and amp_cfg.get("username") and amp_cfg.get("password"):
        excluded = set(amp_cfg.get("excluded_instances", ["ADS01"]))
        return AMPClient(host=amp_cfg["host"], username=amp_cfg["username"], password=amp_cfg["password"], excluded_instances=excluded)
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
    categories = fg.get_service_categories()

    print(f"\n=== Service Categories ({len(categories)}) ===")
    if categories:
        names = [c.get("name", "?") for c in categories]
        print("  " + ", ".join(names))
    else:
        print("  (none)")

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
    amp_instances = (amp.get_instances() or {}) if amp else {}

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

    print(f"\n{'AMP INSTANCE':<32} {'PORTS':<12} {'PROTO':<6} {'VIP / RULE NAME':<50} {'POLICY'}")
    print("-" * 120)
    for instance_name, info in sorted(amp_instances.items()):
        saved = state.get(instance_name, {})
        policy_id = saved.get("policy_id") or saved.get("policy_ids", [None])[0]
        pol_name = _policy_name(instance_name)
        running = f"AMP_{instance_name}" in running_set

        if not info["ports"]:
            status = "running" if running else "stopped"
            print(f"{instance_name:<32} {'—':<12} {'—':<6} {'(no ports)':<50} ({status})")
            continue

        groups = _group_consecutive_ports(info["ports"])
        for i, g in enumerate(groups):
            vip_name = _obj_name(instance_name, g["start_port"], g["end_port"], g["protocol"])
            ports_label = _port_range_str(g["start_port"], g["end_port"])
            prefix = instance_name if i == 0 else ""
            pol_col = f"{pol_name} (id:{policy_id})" if i == 0 else "↑"
            print(f"{prefix:<32} {ports_label:<12} {g['protocol']:<6} {vip_name:<50} {pol_col}")
    print()


# ---------------------------------------------------------------------------
# Dry run
# ---------------------------------------------------------------------------

def cmd_dry_run(cfg: dict):
    """Show what FortiGate rules would be created/deleted without making changes."""
    amp = _make_amp(cfg)
    amp_instances = (amp.get_instances() or {}) if amp else {}

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

    # Build expected rules from ALL AMP instances (grouped into consecutive ranges)
    expected: list[dict] = []
    for instance_name, info in amp_instances.items():
        running = f"AMP_{instance_name}" in running_set
        for g in _group_consecutive_ports(info["ports"]):
            name = _obj_name(instance_name, g["start_port"], g["end_port"], g["protocol"])
            port_range = _port_range_str(g["start_port"], g["end_port"])
            expected.append({"instance": instance_name, "name": name, "port_range": port_range, "proto": g["protocol"], "running": running})

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

    # Group expected rules by instance for display
    by_instance: dict[str, list[dict]] = {}
    for r in expected:
        by_instance.setdefault(r["instance"], []).append(r)

    for instance_name in sorted(by_instance):
        groups = by_instance[instance_name]
        running = groups[0]["running"]
        desired_status = "enable" if running else "disable"
        pol_name = _policy_name(instance_name)

        for r in groups:
            vip_action = "exists" if r["name"] in live_vip_names else "CREATE"
            vip_label = f"VIP  ({ext_ip}:{r['port_range']} → {host_ip}:{r['port_range']} {r['proto'].upper()})"
            print(f"{vip_action:<8} {'':<8} {vip_label:<55} {r['name']}")

        # One service object per instance
        svc_name = _policy_name(instance_name)
        tcp_ranges = [r["port_range"] for r in groups if r["proto"] == "tcp"]
        udp_ranges = [r["port_range"] for r in groups if r["proto"] == "udp"]
        parts = []
        if tcp_ranges:
            parts.append(f"tcp:{' '.join(tcp_ranges)}")
        if udp_ranges:
            parts.append(f"udp:{' '.join(udp_ranges)}")
        svc_action = "exists" if svc_name in live_svc_names else "CREATE"
        if svc_action == "exists":
            live_svc = next((s for s in fg.get_managed_service_objects() if s["name"] == svc_name), {})
            live_tcp = set((live_svc.get("tcp-portrange") or "").split())
            live_udp = set((live_svc.get("udp-portrange") or "").split())
            if live_tcp != set(tcp_ranges) or live_udp != set(udp_ranges):
                svc_action = "UPDATE"
        svc_label = f"Service Object  ({', '.join(parts)})"
        print(f"{svc_action:<8} {'':<8} {svc_label:<55} {svc_name}")

        if pol_name in live_policies:
            current_status = live_policies[pol_name].get("status", "enable")
            current_dstaddr = {d["name"] for d in (live_policies[pol_name].get("dstaddr") or [])}
            expected_vips = {r["name"] for r in groups}
            pol_action = "UPDATE" if (current_status != desired_status or current_dstaddr != expected_vips) else "exists"
        else:
            pol_action = "CREATE"
        vip_count = len(groups)
        print(f"{pol_action:<8} {desired_status:<8} {'Policy  (' + str(vip_count) + ' VIP' + ('s' if vip_count != 1 else '') + ')':<55} {pol_name}")
        print()

    if to_delete:
        for name in sorted(to_delete):
            print(f"{'DELETE':<8} {'—':<8} {'VIP + Service Object':<55} {name}")
        # Orphan policies (old per-port names no longer exist as instance policies)
        orphan_policies = set(live_policies) - {_policy_name(n) for n in by_instance}
        for name in sorted(orphan_policies):
            print(f"{'DELETE':<8} {'—':<8} {'Policy':<55} {name}")
        print()

    if not fw_reachable:
        return
    vip_creates = sum(1 for r in expected if r["name"] not in live_vip_names)
    pol_creates = sum(1 for inst in by_instance if _policy_name(inst) not in live_policies)
    pol_updates = sum(1 for inst, grps in by_instance.items()
                      if _policy_name(inst) in live_policies and (
                          live_policies[_policy_name(inst)].get("status") != ("enable" if grps[0]["running"] else "disable")
                          or {d["name"] for d in (live_policies[_policy_name(inst)].get("dstaddr") or [])} != {r["name"] for r in grps}
                      ))
    deletes = len(to_delete)
    print(f"Summary: {vip_creates} VIPs to create, {pol_creates} policies to create, {pol_updates} policies to update, {deletes} VIPs to delete")


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
            instance_id = instance.get("InstanceID", "")
            endpoints = instance.get("ApplicationEndpoints", [])

            print(f"\n{'='*60}")
            print(f"  InstanceName : {name}")
            print(f"  ModuleName   : {module}")
            print(f"  FriendlyName : {friendly}")
            print(f"  Running      : {running}")
            print(f"  InstanceID   : {instance_id}")

            print(f"  ApplicationEndpoints ({len(endpoints)}):")
            if endpoints:
                for ep in endpoints:
                    print(f"    DisplayName={ep.get('DisplayName')!r:30s}  Endpoint={ep.get('Endpoint')!r}")
            else:
                print("    (none)")

            # Per-instance network info (authoritative port source)
            if instance_id:
                _PROTO_NAMES = {0: "tcp", 1: "udp", 2: "tcp+udp"}
                ni_data = client._post(
                    "/API/ADSModule/GetInstanceNetworkInfo",
                    {"InstanceName": name},
                    wrap=False,
                )
                if ni_data is None:
                    print("  NetworkInfo  : (request failed)")
                elif isinstance(ni_data, list):
                    print(f"  NetworkInfo ({len(ni_data)}):")
                    for ni in ni_data:
                        fw = "FW" if ni.get("IsFirewallTarget") else "  "
                        proto = _PROTO_NAMES.get(ni.get("Protocol", 0), "?")
                        desc = ni.get("Description", "")
                        port = ni.get("PortNumber", "?")
                        print(f"    [{fw}] {port:<6} {proto:<8} {desc}")
                else:
                    print(f"  NetworkInfo (raw): {json.dumps(ni_data, indent=4)}")
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
