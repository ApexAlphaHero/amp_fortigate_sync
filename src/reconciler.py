import logging
import re
import socket
from typing import Optional

from amp_client import AMPClient
from docker_inspector import DockerInspector
from fortigate_client import FortigateClient
from state_manager import StateManager

logger = logging.getLogger(__name__)


def _ports_key(ports: list[dict]) -> frozenset:
    return frozenset((p["host_port"], p["protocol"]) for p in ports)


def _safe_name(raw: str) -> str:
    return re.sub(r"[^a-zA-Z0-9_-]", "-", raw)[:63]


def _obj_name(label: str, start_port: int, end_port: int, proto: str) -> str:
    if start_port == end_port:
        return _safe_name(f"amp-sync-{label}-{start_port}-{proto}")
    return _safe_name(f"amp-sync-{label}-{start_port}-{end_port}-{proto}")


def _port_range_str(start: int, end: int) -> str:
    return f"{start}-{end}" if start != end else str(start)


def _group_consecutive_ports(ports: list[dict]) -> list[dict]:
    """Group consecutive same-protocol ports into ranges.

    Returns list of {start_port, end_port, protocol} dicts.
    Non-consecutive ports of the same protocol produce separate groups.
    """
    by_proto: dict[str, list[int]] = {}
    for p in ports:
        by_proto.setdefault(p["protocol"], []).append(p["host_port"])

    groups = []
    for proto, port_list in sorted(by_proto.items()):
        sorted_ports = sorted(set(port_list))
        start = end = sorted_ports[0]
        for port in sorted_ports[1:]:
            if port == end + 1:
                end = port
            else:
                groups.append({"start_port": start, "end_port": end, "protocol": proto})
                start = end = port
        groups.append({"start_port": start, "end_port": end, "protocol": proto})
    return groups


class Reconciler:
    def __init__(
        self,
        docker_inspector: DockerInspector,
        state_manager: StateManager,
        fortigate_client: FortigateClient,
        ext_ip: str,
        host_ip: str = "",
        amp_client: Optional[AMPClient] = None,
    ):
        self._docker = docker_inspector
        self._state = state_manager
        self._fg = fortigate_client
        self._ext_ip = ext_ip
        self._host_ip = host_ip or self._detect_host_ip()
        self._amp = amp_client
        self._ssl_ssh_profile: Optional[str] = None

    def reconcile(self) -> dict:
        amp_instances = self._amp.get_instances() if self._amp else {}

        # Map docker container name → running status
        running_set = {
            c["name"] for c in self._docker.get_all_containers()
            if c["status"] == "running"
        }

        live_vips = {v["name"]: v for v in self._fg.get_managed_vips()}
        live_services = {s["name"]: s for s in self._fg.get_managed_service_objects()}
        live_policies = {p["name"]: p for p in self._fg.get_managed_policies()}

        expected_vip_names: set[str] = set()
        stats = {"added": 0, "removed": 0, "updated": 0, "errors": 0}

        for instance_name, info in amp_instances.items():
            running = f"AMP_{instance_name}" in running_set
            for g in _group_consecutive_ports(info["ports"]):
                expected_vip_names.add(_obj_name(instance_name, g["start_port"], g["end_port"], g["protocol"]))
            try:
                result = self._ensure_rules(
                    instance_name, info["ports"], running,
                    live_vips, live_services, live_policies,
                )
                if result == "created":
                    stats["added"] += 1
                elif result == "updated":
                    stats["updated"] += 1
            except Exception as e:
                logger.error("Failed to ensure rules for %s: %s", instance_name, e)
                stats["errors"] += 1

        # Delete orphans — amp-sync- VIPs with no matching AMP instance
        for vip_name in set(live_vips) - expected_vip_names:
            try:
                self._delete_port_rules(vip_name, live_policies)
                self._remove_state_by_vip(vip_name)
                stats["removed"] += 1
            except Exception as e:
                logger.error("Failed to delete orphan rules for %s: %s", vip_name, e)
                stats["errors"] += 1

        logger.info("Reconcile: +%d -%d ~%d errors=%d",
                    stats["added"], stats["removed"], stats["updated"], stats["errors"])
        return stats

    # ------------------------------------------------------------------
    # Per-instance rule management
    # ------------------------------------------------------------------

    def _ensure_rules(
        self,
        instance_name: str,
        ports: list[dict],
        running: bool,
        live_vips: dict,
        live_services: dict,
        live_policies: dict,
    ) -> str:
        saved = self._state.get(instance_name)
        desired_status = "enable" if running else "disable"
        result = "unchanged"

        # Rebuild if ports changed
        if saved and _ports_key(saved["ports"]) != _ports_key(ports):
            logger.info("Port change for %s — rebuilding rules", instance_name)
            for vip_name in saved.get("vip_names", []):
                self._delete_port_rules(vip_name, live_policies)
                live_vips.pop(vip_name, None)
                live_services.pop(vip_name, None)
                live_policies.pop(vip_name, None)
            saved = None

        vip_names: list[str] = []
        service_names: list[str] = []
        policy_ids: list = list(saved["policy_ids"]) if saved else []

        for g in _group_consecutive_ports(ports):
            name = _obj_name(instance_name, g["start_port"], g["end_port"], g["protocol"])
            port_range = _port_range_str(g["start_port"], g["end_port"])
            proto = g["protocol"]

            if name not in live_vips:
                self._fg.create_vip(
                    name=name, ext_ip=self._ext_ip, ext_port=port_range,
                    mapped_ip=self._host_ip, mapped_port=port_range, protocol=proto,
                )
                result = "created"

            if name not in live_services:
                self._fg.create_service_object(name=name, port=port_range, protocol=proto)
                result = "created"

            if name not in live_policies:
                resp = self._fg.create_policy(
                    name=name, vip_name=name, service_obj_name=name,
                    status=desired_status, ssl_ssh_profile=self._ssl_ssh_profile,
                )
                pid = (resp.get("results") or [{}])[0].get("mkey")
                if pid is not None:
                    policy_ids.append(pid)
                result = "created"
            else:
                current_status = live_policies[name].get("status", "enable")
                if current_status != desired_status:
                    pid = live_policies[name].get("policyid") or live_policies[name].get("id")
                    if pid is not None:
                        self._fg.update_policy_status(pid, desired_status)
                        if result == "unchanged":
                            result = "updated"

            vip_names.append(name)
            service_names.append(name)

        self._state.save(instance_name, {
            "ports": ports,
            "running": running,
            "policy_ids": policy_ids,
            "vip_names": vip_names,
            "service_obj_names": service_names,
        })
        return result

    # ------------------------------------------------------------------
    # Deletion helpers
    # ------------------------------------------------------------------

    def _delete_port_rules(self, vip_name: str, live_policies: dict):
        if vip_name in live_policies:
            pid = live_policies[vip_name].get("policyid") or live_policies[vip_name].get("id")
            if pid is not None:
                self._fg.delete_policy(pid)
        self._fg.delete_service_object(vip_name)
        self._fg.delete_vip(vip_name)

    def _remove_state_by_vip(self, vip_name: str):
        for instance_name, data in self._state.load_all().items():
            if vip_name in data.get("vip_names", []):
                remaining = [v for v in data["vip_names"] if v != vip_name]
                if not remaining:
                    self._state.remove(instance_name)
                else:
                    data["vip_names"] = remaining
                    data["service_obj_names"] = [s for s in data["service_obj_names"] if s != vip_name]
                    self._state.save(instance_name, data)
                return

    # ------------------------------------------------------------------

    @staticmethod
    def _detect_host_ip() -> str:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except OSError:
            return "127.0.0.1"
