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

    def get_running_containers(self) -> list[dict]:
        filters = {"status": "running"}
        if self._label_filter:
            filters["label"] = self._label_filter

        try:
            containers = self._client.containers.list(filters=filters)
        except docker.errors.DockerException as e:
            logger.error("Failed to list Docker containers: %s", e)
            return []

        result = []
        for c in containers:
            ports = self._extract_ports(c.ports)
            result.append({
                "id": c.id,
                "name": c.name,
                "image": c.image.tags[0] if c.image.tags else c.image.short_id,
                "ports": ports,
            })
        return result

    def _extract_ports(self, port_bindings: dict) -> list[dict]:
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

    def listen_events(self):
        """Generator that yields Docker start/stop events as dicts."""
        try:
            for event in self._client.events(decode=True, filters={"type": "container"}):
                action = event.get("Action", "")
                if action in ("start", "die", "stop", "kill"):
                    yield event
        except docker.errors.DockerException as e:
            logger.error("Docker event stream error: %s", e)
