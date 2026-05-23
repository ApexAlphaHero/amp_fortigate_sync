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
            host_net = self._is_host_network(c)
            ports = self._extract_ports_host_net(c) if host_net else self._extract_ports_bridge(c.ports)
            if host_net and not ports:
                logger.debug("%s uses host networking but has no ExposedPorts", c.name)
            result.append({
                "id": c.id,
                "name": c.name,
                "image": c.image.tags[0] if c.image.tags else c.image.short_id,
                "ports": ports,
                "host_network": host_net,
            })
        return result

    @staticmethod
    def _is_host_network(container) -> bool:
        return container.attrs.get("HostConfig", {}).get("NetworkMode", "") == "host"

    @staticmethod
    def _extract_ports_bridge(port_bindings: dict) -> list[dict]:
        """Extract ports from containers using bridge/mapped networking (-p flag)."""
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
        """Extract ports from host-network containers via their ExposedPorts config.

        With --network host the container shares the host's network stack, so
        there are no Docker port mappings. The container port IS the host port.
        """
        exposed = container.attrs.get("Config", {}).get("ExposedPorts") or {}
        ports = []
        for port_proto in exposed:
            # format is "8080/tcp" or "27015/udp"
            if "/" in port_proto:
                port_str, proto = port_proto.split("/", 1)
            else:
                port_str, proto = port_proto, "tcp"
            try:
                ports.append({"host_port": int(port_str), "protocol": proto})
            except ValueError:
                logger.warning("Could not parse exposed port: %s", port_proto)
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
