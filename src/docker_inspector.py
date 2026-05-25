import logging
from typing import Optional

import docker
import docker.errors

logger = logging.getLogger(__name__)


class DockerInspector:
    def __init__(self, socket_url: str = "unix:///var/run/docker.sock", label_filter: Optional[str] = None):
        self._socket_url = socket_url
        self._label_filter = label_filter or ""
        self._client = docker.DockerClient(base_url=socket_url)

    def _list_containers(self, running_only: bool) -> list:
        filters = {}
        if running_only:
            filters["status"] = "running"
        if self._label_filter:
            filters["label"] = self._label_filter
        try:
            return self._client.containers.list(all=not running_only, filters=filters)
        except docker.errors.DockerException as e:
            logger.error("Failed to list Docker containers: %s", e)
            return []

    def _to_dict(self, c) -> dict:
        if self._is_host_network(c):
            ports = self._extract_ports_host_net(c)
        else:
            ports = self._extract_ports_bridge(c.ports)
        return {
            "id": c.id,
            "name": c.name,
            "status": c.status,
            "image": c.image.tags[0] if c.image.tags else c.image.short_id,
            "ports": ports,
            "host_network": self._is_host_network(c),
        }

    def get_running_containers(self) -> list[dict]:
        return [self._to_dict(c) for c in self._list_containers(running_only=True)]

    def get_all_containers(self) -> list[dict]:
        return [self._to_dict(c) for c in self._list_containers(running_only=False)]

    # ------------------------------------------------------------------
    # Port extraction
    # ------------------------------------------------------------------

    @staticmethod
    def _extract_ports_bridge(port_bindings: dict) -> list[dict]:
        ports = []
        for container_port, bindings in (port_bindings or {}).items():
            if bindings is None:
                continue
            proto = "tcp"
            if "/" in container_port:
                _, proto = container_port.split("/", 1)
            for binding in bindings:
                host_port = binding.get("HostPort")
                if host_port:
                    ports.append({"host_port": int(host_port), "protocol": proto})
        return ports

    @staticmethod
    def _extract_ports_host_net(container) -> list[dict]:
        """Read ExposedPorts from image config (host-network containers have no mappings)."""
        exposed = container.attrs.get("Config", {}).get("ExposedPorts") or {}
        ports = []
        for port_proto in exposed:
            if "/" in port_proto:
                port_str, proto = port_proto.split("/", 1)
            else:
                port_str, proto = port_proto, "tcp"
            try:
                ports.append({"host_port": int(port_str), "protocol": proto})
            except ValueError:
                pass
        return ports

    @staticmethod
    def _is_host_network(container) -> bool:
        return container.attrs.get("HostConfig", {}).get("NetworkMode", "") == "host"

    def listen_events(self):
        """Generator that yields Docker start/stop events as dicts."""
        try:
            for event in self._client.events(decode=True, filters={"type": "container"}):
                action = event.get("Action", "")
                if action in ("start", "die", "stop", "kill"):
                    yield event
        except docker.errors.DockerException as e:
            logger.error("Docker event stream error: %s", e)
