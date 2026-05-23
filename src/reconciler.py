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


def _addr_name_for(label: str) -> str:
    return _safe_name(f"amp-sync-{label}")


def _policy_name_for(label: str, port: int, protocol: str) -> str:
    return _safe_name(f"amp-sync-{label}-{port}-{protocol}")


class Reconciler:
    def __init__(
        self,
        docker_inspector: DockerInspector,
        state_manager: StateManager,
        fortigate_client: FortigateClient,
        amp_client: Optional[AMPClient] = None,
        interfaces: Optional[list[str]] = None,
    ):
        self._docker = docker_inspector
        self._state = state_manager
        self._fg = fortigate_client
        self._amp = amp_client
        self._interfaces = interfaces or ["port1"]

    def reconcile(self) -> dict:
        # --- collect current reality from both sides ---
        current_containers = {c["id"]: c for c in self._docker.get_running_containers()}
        amp_instances = self._amp.get_instances() if self._amp else {}

        # Pull every [amp-sync]-tagged object from FortiGate
        live_policies = self._fg.get_managed_policies()
        live_addr_objs = self._fg.get_managed_address_objects()

        # name → full object, for quick existence checks
        existing_policy_names: dict[str, dict] = {p["name"]: p for p in live_policies}
        existing_addr_names: dict[str, dict] = {a["name"]: a for a in live_addr_objs}

        # addr_obj_name → list of policy ids that reference it (for orphan cleanup)
        addr_to_policy_ids: dict[str, list] = {}
        for p in live_policies:
            pid = p.get("policyid") or p.get("id")
            for dst in p.get("dstaddr", []):
                addr = dst.get("name", "")
                if addr:
                    addr_to_policy_ids.setdefault(addr, []).append(pid)

        stats = {"added": 0, "removed": 0, "updated": 0, "errors": 0}

        # --- compute expected addr names for running containers ---
        expected_addr_names: set[str] = set()
        for cid, c in current_containers.items():
            label = self._resolve_label(c, amp_instances)
            expected_addr_names.add(_addr_name_for(label))

        # --- ensure rules exist for every running container ---
        host_ip = self._get_docker_host_ip()
        for cid, c in current_containers.items():
            try:
                added = self._ensure_rules(
                    cid, c, amp_instances, host_ip,
                    existing_policy_names, existing_addr_names,
                )
                if added:
                    stats["added"] += 1
            except Exception as e:
                logger.error("Failed to ensure rules for container %s (%s): %s", cid[:12], c["name"], e)
                stats["errors"] += 1

        # --- delete orphan addr objects (and their policies) ---
        # An addr object is an orphan if it's tagged [amp-sync] but no running
        # container expects it.  This catches deleted instances even if SQLite
        # state was lost.
        orphan_addr_names = set(existing_addr_names) - expected_addr_names
        for addr_name in orphan_addr_names:
            try:
                self._delete_addr_and_policies(addr_name, addr_to_policy_ids)
                # Clean up SQLite if we have a record keyed to this addr name
                self._remove_state_by_addr(addr_name)
                stats["removed"] += 1
            except Exception as e:
                logger.error("Failed to delete orphan rules for %s: %s", addr_name, e)
                stats["errors"] += 1

        logger.info(
            "Reconcile complete: +%d -%d ~%d errors=%d",
            stats["added"], stats["removed"], stats["updated"], stats["errors"],
        )
        return stats

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _resolve_label(self, container: dict, amp_instances: dict) -> str:
        if self._amp:
            return self._amp.resolve_container_name(container["name"], amp_instances)
        return container["name"]

    def _ensure_rules(
        self,
        container_id: str,
        container: dict,
        amp_instances: dict,
        host_ip: str,
        existing_policy_names: dict,
        existing_addr_names: dict,
    ) -> bool:
        """Create any missing address object or policies for this container.
        Returns True if anything was created (i.e. this was a net-new container)."""
        label = self._resolve_label(container, amp_instances)
        addr_name = _addr_name_for(label)

        saved = self._state.get(container_id)
        created_anything = False

        # Check for port changes vs saved state
        if saved and _ports_key(saved["ports"]) != _ports_key(container["ports"]):
            logger.info("Port change detected for %s — rebuilding rules", container["name"])
            self._delete_addr_and_policies(
                addr_name,
                {addr_name: saved.get("policy_ids", [])},
            )
            existing_addr_names.pop(addr_name, None)
            for pname in [_policy_name_for(label, p["host_port"], p["protocol"]) for p in saved["ports"]]:
                existing_policy_names.pop(pname, None)

        # Create address object if missing on FortiGate
        if addr_name not in existing_addr_names:
            self._fg.create_address_object(addr_name, host_ip)
            created_anything = True

        # Create any missing policies
        policy_ids = list(saved["policy_ids"]) if saved else []
        for port_info in container["ports"]:
            pname = _policy_name_for(label, port_info["host_port"], port_info["protocol"])
            if pname not in existing_policy_names:
                result = self._fg.create_policy(
                    name=pname,
                    port=port_info["host_port"],
                    protocol=port_info["protocol"],
                    address_obj_name=addr_name,
                    interfaces=self._interfaces,
                )
                pid = (result.get("results") or [{}])[0].get("mkey")
                if pid is not None:
                    policy_ids.append(pid)
                created_anything = True

        # Keep SQLite in sync
        self._state.save(container_id, {
            "name": label,
            "ports": container["ports"],
            "policy_ids": policy_ids,
            "address_obj_name": addr_name,
        })
        return created_anything

    def _delete_addr_and_policies(self, addr_name: str, addr_to_policy_ids: dict):
        for pid in addr_to_policy_ids.get(addr_name, []):
            self._fg.delete_policy(pid)
        self._fg.delete_address_object(addr_name)

    def _remove_state_by_addr(self, addr_name: str):
        for cid, data in self._state.load_all().items():
            if data.get("address_obj_name") == addr_name:
                self._state.remove(cid)
                return

    @staticmethod
    def _get_docker_host_ip() -> str:
        try:
            return socket.gethostbyname(socket.gethostname())
        except OSError:
            return "127.0.0.1"
