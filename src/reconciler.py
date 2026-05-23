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


def _obj_name(label: str, port: int, proto: str) -> str:
    """Shared naming for VIP, service object, and policy — all use the same name."""
    return _safe_name(f"amp-sync-{label}-{port}-{proto}")


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

    def reconcile(self) -> dict:
        current_containers = {c["id"]: c for c in self._docker.get_running_containers()}
        amp_instances = self._amp.get_instances() if self._amp else {}

        # Merge AMP port info into containers that Docker reports as having none
        for c in current_containers.values():
            if not c["ports"]:
                label = self._resolve_label(c, amp_instances)
                amp_ports = amp_instances.get(label, {}).get("ports", [])
                if amp_ports:
                    logger.debug("Using AMP ports for %s: %s", c["name"], amp_ports)
                    c["ports"] = amp_ports

        # Pull live [amp-sync]-tagged objects from FortiGate
        live_vips = {v["name"]: v for v in self._fg.get_managed_vips()}
        live_services = {s["name"]: s for s in self._fg.get_managed_service_objects()}
        live_policies = {p["name"]: p for p in self._fg.get_managed_policies()}

        # Build expected VIP names from running containers
        expected_vip_names: set[str] = set()
        for c in current_containers.values():
            label = self._resolve_label(c, amp_instances)
            for port_info in c["ports"]:
                expected_vip_names.add(_obj_name(label, port_info["host_port"], port_info["protocol"]))

        stats = {"added": 0, "removed": 0, "errors": 0}
        host_ip = self._host_ip

        # Ensure rules exist for every running container
        for cid, container in current_containers.items():
            try:
                created = self._ensure_rules(
                    cid, container, amp_instances, host_ip,
                    live_vips, live_services, live_policies,
                )
                if created:
                    stats["added"] += 1
            except Exception as e:
                logger.error("Failed to ensure rules for %s (%s): %s", cid[:12], container["name"], e)
                stats["errors"] += 1

        # Delete orphan objects — any [amp-sync] VIP with no matching running container
        orphan_vip_names = set(live_vips) - expected_vip_names
        for vip_name in orphan_vip_names:
            try:
                self._delete_port_rules(vip_name, live_policies)
                self._remove_state_by_vip(vip_name)
                stats["removed"] += 1
            except Exception as e:
                logger.error("Failed to delete orphan rules for %s: %s", vip_name, e)
                stats["errors"] += 1

        logger.info("Reconcile: +%d -%d errors=%d", stats["added"], stats["removed"], stats["errors"])
        return stats

    # ------------------------------------------------------------------
    # Per-container rule management
    # ------------------------------------------------------------------

    def _ensure_rules(
        self,
        container_id: str,
        container: dict,
        amp_instances: dict,
        host_ip: str,
        live_vips: dict,
        live_services: dict,
        live_policies: dict,
    ) -> bool:
        label = self._resolve_label(container, amp_instances)
        saved = self._state.get(container_id)
        created_anything = False

        # Detect port changes — tear down old per-port objects before rebuilding
        if saved and _ports_key(saved["ports"]) != _ports_key(container["ports"]):
            logger.info("Port change for %s — rebuilding rules", container["name"])
            for vip_name in saved.get("vip_names", []):
                self._delete_port_rules(vip_name, live_policies)
                live_vips.pop(vip_name, None)
                live_services.pop(vip_name, None)
                live_policies.pop(vip_name, None)

        vip_names: list[str] = []
        service_names: list[str] = []
        policy_ids: list = list(saved["policy_ids"]) if saved else []

        for port_info in container["ports"]:
            name = _obj_name(label, port_info["host_port"], port_info["protocol"])
            port = port_info["host_port"]
            proto = port_info["protocol"]

            if name not in live_vips:
                self._fg.create_vip(
                    name=name,
                    ext_ip=self._ext_ip,
                    ext_port=port,
                    mapped_ip=host_ip,
                    mapped_port=port,
                    protocol=proto,
                )
                created_anything = True

            if name not in live_services:
                self._fg.create_service_object(name=name, port=port, protocol=proto)
                created_anything = True

            if name not in live_policies:
                result = self._fg.create_policy(
                    name=name,
                    vip_name=name,
                    service_obj_name=name,
                )
                pid = (result.get("results") or [{}])[0].get("mkey")
                if pid is not None:
                    policy_ids.append(pid)
                created_anything = True

            vip_names.append(name)
            service_names.append(name)

        self._state.save(container_id, {
            "name": label,
            "ports": container["ports"],
            "policy_ids": policy_ids,
            "vip_names": vip_names,
            "service_obj_names": service_names,
        })
        return created_anything

    # ------------------------------------------------------------------
    # Deletion helpers
    # ------------------------------------------------------------------

    def _delete_port_rules(self, vip_name: str, live_policies: dict):
        """Delete the policy, service object, and VIP for a single port mapping."""
        if vip_name in live_policies:
            pid = live_policies[vip_name].get("policyid") or live_policies[vip_name].get("id")
            if pid is not None:
                self._fg.delete_policy(pid)
        self._fg.delete_service_object(vip_name)
        self._fg.delete_vip(vip_name)

    def _remove_state_by_vip(self, vip_name: str):
        for cid, data in self._state.load_all().items():
            if vip_name in data.get("vip_names", []):
                remaining_vips = [v for v in data["vip_names"] if v != vip_name]
                if not remaining_vips:
                    self._state.remove(cid)
                else:
                    data["vip_names"] = remaining_vips
                    data["service_obj_names"] = [s for s in data["service_obj_names"] if s != vip_name]
                    self._state.save(cid, data)
                return

    # ------------------------------------------------------------------

    def _resolve_label(self, container: dict, amp_instances: dict) -> str:
        if self._amp:
            return self._amp.resolve_container_name(container["name"], amp_instances)
        return container["name"]

    @staticmethod
    def _detect_host_ip() -> str:
        """Reliably find this machine's outbound IP by connecting a UDP socket.
        No traffic is actually sent — the OS picks the right source interface."""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except OSError:
            return "127.0.0.1"
