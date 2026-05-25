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


def _safe_name(raw: str, max_len: int = 79) -> str:
    return re.sub(r"[^a-zA-Z0-9_-]", "-", raw)[:max_len]


def _obj_name(label: str, start_port: int, end_port: int, proto: str) -> str:
    if start_port == end_port:
        return _safe_name(f"amp-sync-{label}-{start_port}-{proto}")
    return _safe_name(f"amp-sync-{label}-{start_port}-{end_port}-{proto}")


def _policy_name(label: str) -> str:
    return _safe_name(f"amp-sync-{label}", max_len=35)


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
        self._policy_insert_after: Optional[int] = None
        self._service_category: Optional[str] = None
        self._dstintf: str = "any"
        self._srcaddr: list[str] = ["all"]

    def reconcile(self) -> dict:
        if self._service_category:
            self._fg.ensure_service_category(self._service_category)

        amp_instances = self._amp.get_instances() if self._amp else {}

        running_set = {
            c["name"] for c in self._docker.get_all_containers()
            if c["status"] == "running"
        }

        live_vips = {v["name"]: v for v in self._fg.get_managed_vips()}
        live_services = {s["name"]: s for s in self._fg.get_managed_service_objects()}
        live_policies = {p["name"]: p for p in self._fg.get_managed_policies()}

        expected_vip_names: set[str] = set()
        expected_instance_names: set[str] = set()
        stats = {"added": 0, "removed": 0, "updated": 0, "errors": 0}

        for instance_name, info in amp_instances.items():
            running = f"AMP_{instance_name}" in running_set
            for g in _group_consecutive_ports(info["ports"]):
                expected_vip_names.add(_obj_name(instance_name, g["start_port"], g["end_port"], g["protocol"]))
            expected_instance_names.add(_policy_name(instance_name))
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

        # Delete orphan policies first (they reference VIPs — must go before VIP deletion)
        for name in set(live_policies) - expected_instance_names:
            try:
                pid = live_policies[name].get("policyid") or live_policies[name].get("id")
                if pid is not None:
                    self._fg.delete_policy(pid)
                stats["removed"] += 1
            except Exception as e:
                logger.error("Failed to delete orphan policy %s: %s", name, e)
                stats["errors"] += 1

        # Delete orphan VIPs (now safe — no policies reference them)
        for vip_name in set(live_vips) - expected_vip_names:
            try:
                self._fg.delete_vip(vip_name)
                self._remove_state_by_vip(vip_name)
                stats["removed"] += 1
            except Exception as e:
                logger.error("Failed to delete orphan VIP %s: %s", vip_name, e)
                stats["errors"] += 1

        # Delete orphan service objects
        for name in set(live_services) - expected_instance_names:
            try:
                self._fg.delete_service_object(name)
                stats["removed"] += 1
            except Exception as e:
                logger.error("Failed to delete orphan service object %s: %s", name, e)
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
        inst_name = _policy_name(instance_name)  # amp-sync-{instance} — used for service obj + policy

        # Rebuild VIPs and policy if ports changed (service object is updated in-place)
        if saved and _ports_key(saved["ports"]) != _ports_key(ports):
            logger.info("Port change for %s — rebuilding VIPs and policy", instance_name)
            for vip_name in saved.get("vip_names", []):
                self._fg.delete_vip(vip_name)
                live_vips.pop(vip_name, None)
            if inst_name in live_policies:
                pid = live_policies[inst_name].get("policyid") or live_policies[inst_name].get("id")
                if pid is not None:
                    self._fg.delete_policy(pid)
                live_policies.pop(inst_name)
            saved = None

        groups = _group_consecutive_ports(ports)
        tcp_ranges = [_port_range_str(g["start_port"], g["end_port"]) for g in groups if g["protocol"] == "tcp"]
        udp_ranges = [_port_range_str(g["start_port"], g["end_port"]) for g in groups if g["protocol"] == "udp"]

        # VIPs — one per port group
        vip_names: list[str] = []
        for g in groups:
            vip_name = _obj_name(instance_name, g["start_port"], g["end_port"], g["protocol"])
            if vip_name not in live_vips:
                self._fg.create_vip(
                    name=vip_name, ext_ip=self._ext_ip,
                    ext_port=_port_range_str(g["start_port"], g["end_port"]),
                    mapped_ip=self._host_ip,
                    mapped_port=_port_range_str(g["start_port"], g["end_port"]),
                    protocol=g["protocol"],
                )
                result = "created"
            vip_names.append(vip_name)

        # Service object — one per instance, all TCP + UDP ranges combined
        if inst_name not in live_services:
            self._fg.create_service_object(inst_name, tcp_ranges, udp_ranges, self._service_category)
            result = "created"
        else:
            current = live_services[inst_name]
            current_tcp = set((current.get("tcp-portrange") or "").split())
            current_udp = set((current.get("udp-portrange") or "").split())
            if current_tcp != set(tcp_ranges) or current_udp != set(udp_ranges):
                self._fg.update_service_object(inst_name, tcp_ranges, udp_ranges, self._service_category)
                if result == "unchanged":
                    result = "updated"

        # Policy — one per instance
        policy_id = saved.get("policy_id") if saved else None
        svc_list = [inst_name]

        if inst_name not in live_policies:
            resp = self._fg.create_policy(
                name=inst_name,
                vip_names=vip_names,
                service_obj_names=svc_list,
                status=desired_status,
                ssl_ssh_profile=self._ssl_ssh_profile,
                dstintf=self._dstintf,
                srcaddr=self._srcaddr,
            )
            policy_id = resp.get("mkey")
            result = "created"
        else:
            current = live_policies[inst_name]
            current_status = current.get("status", "enable")
            current_dstaddr = {d["name"] for d in (current.get("dstaddr") or [])}
            needs_update = (
                current_status != desired_status
                or current_dstaddr != set(vip_names)
            )
            if needs_update:
                pid = current.get("policyid") or current.get("id")
                if pid is not None:
                    self._fg.update_policy(pid, vip_names, svc_list, desired_status)
                    policy_id = pid
                if result == "unchanged":
                    result = "updated"

        self._state.save(instance_name, {
            "ports": ports,
            "running": running,
            "policy_id": policy_id,
            "vip_names": vip_names,
        })
        return result

    # ------------------------------------------------------------------
    # State helpers
    # ------------------------------------------------------------------

    def _remove_state_by_vip(self, vip_name: str):
        for instance_name, data in self._state.load_all().items():
            if vip_name in data.get("vip_names", []):
                remaining = [v for v in data["vip_names"] if v != vip_name]
                if not remaining:
                    self._state.remove(instance_name)
                else:
                    data["vip_names"] = remaining
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
