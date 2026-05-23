import logging
import re
import socket
from typing import Optional

from amp_client import AMPClient
from docker_inspector import DockerInspector
from fortigate_client import FortigateClient
from state_manager import StateManager

logger = logging.getLogger(__name__)


def _ports_changed(saved_ports: list[dict], current_ports: list[dict]) -> bool:
    normalize = lambda ports: sorted((p["host_port"], p["protocol"]) for p in ports)
    return normalize(saved_ports) != normalize(current_ports)


def _safe_name(raw: str) -> str:
    return re.sub(r"[^a-zA-Z0-9_-]", "-", raw)[:63]


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
        current_containers = {c["id"]: c for c in self._docker.get_running_containers()}
        saved_state = self._state.load_all()

        amp_instances = self._amp.get_instances() if self._amp else {}

        added = set(current_containers) - set(saved_state)
        removed = set(saved_state) - set(current_containers)
        common = set(current_containers) & set(saved_state)
        changed = {cid for cid in common if _ports_changed(saved_state[cid]["ports"], current_containers[cid]["ports"])}

        stats = {"added": 0, "removed": 0, "updated": 0, "errors": 0}

        for cid in added:
            try:
                self._create_rules(cid, current_containers[cid], amp_instances)
                stats["added"] += 1
            except Exception as e:
                logger.error("Failed to create rules for container %s: %s", cid[:12], e)
                stats["errors"] += 1

        for cid in removed:
            try:
                self._delete_rules(cid, saved_state[cid])
                stats["removed"] += 1
            except Exception as e:
                logger.error("Failed to delete rules for container %s: %s", cid[:12], e)
                stats["errors"] += 1

        for cid in changed:
            try:
                self._delete_rules(cid, saved_state[cid])
                self._create_rules(cid, current_containers[cid], amp_instances)
                stats["updated"] += 1
            except Exception as e:
                logger.error("Failed to update rules for container %s: %s", cid[:12], e)
                stats["errors"] += 1

        logger.info("Reconcile complete: +%d -%d ~%d errors=%d",
                    stats["added"], stats["removed"], stats["updated"], stats["errors"])
        return stats

    def _resolve_label(self, container: dict, amp_instances: dict) -> str:
        if self._amp:
            return self._amp.resolve_container_name(container["name"], amp_instances)
        return container["name"]

    def _create_rules(self, container_id: str, container: dict, amp_instances: dict):
        label = self._resolve_label(container, amp_instances)
        addr_name = _safe_name(f"amp-sync-{label}")

        host_ip = self._get_docker_host_ip()
        self._fg.create_address_object(addr_name, host_ip)

        policy_ids = []
        for port_info in container["ports"]:
            policy_name = _safe_name(f"amp-sync-{label}-{port_info['host_port']}")
            result = self._fg.create_policy(
                name=policy_name,
                port=port_info["host_port"],
                protocol=port_info["protocol"],
                address_obj_name=addr_name,
                interfaces=self._interfaces,
            )
            pid = (result.get("results") or [{}])[0].get("mkey") if result else None
            if pid is not None:
                policy_ids.append(pid)

        self._state.save(container_id, {
            "name": label,
            "ports": container["ports"],
            "policy_ids": policy_ids,
            "address_obj_name": addr_name,
        })

    def _delete_rules(self, container_id: str, saved: dict):
        for pid in saved.get("policy_ids", []):
            self._fg.delete_policy(pid)
        addr_name = saved.get("address_obj_name")
        if addr_name:
            self._fg.delete_address_object(addr_name)
        self._state.remove(container_id)

    @staticmethod
    def _get_docker_host_ip() -> str:
        try:
            return socket.gethostbyname(socket.gethostname())
        except OSError:
            return "127.0.0.1"
