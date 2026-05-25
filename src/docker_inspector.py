import glob
import logging
import os
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
            if self._is_host_network(c):
                ports = self._get_ports_from_proc(c)
                if not ports:
                    ports = self._extract_ports_host_net(c)
            else:
                ports = self._extract_ports_bridge(c.ports)

            result.append({
                "id": c.id,
                "name": c.name,
                "image": c.image.tags[0] if c.image.tags else c.image.short_id,
                "ports": ports,
                "host_network": self._is_host_network(c),
            })
        return result

    # ------------------------------------------------------------------
    # Port extraction methods
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
        """Fallback: read ExposedPorts from image config."""
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
    def _get_ports_from_proc(container) -> list[dict]:
        """Read listening ports directly from /proc for the container's process tree.

        Works for host-network containers where Docker reports no port mappings.
        Requires root (or CAP_SYS_PTRACE) to read /proc/{pid}/fd symlinks.
        """
        pid = container.attrs.get("State", {}).get("Pid", 0)
        if not pid:
            return []

        # BFS to collect all PIDs in the container's process tree
        all_pids: set[int] = set()
        queue = [pid]
        while queue:
            current = queue.pop(0)
            if current in all_pids:
                continue
            all_pids.add(current)
            for status_path in glob.glob("/proc/[0-9]*/status"):
                try:
                    cpid = int(status_path.split("/")[2])
                    with open(status_path) as f:
                        for line in f:
                            if line.startswith("PPid:"):
                                if int(line.split()[1]) == current and cpid not in all_pids:
                                    queue.append(cpid)
                                break
                except (ValueError, OSError):
                    pass

        # Collect socket inodes owned by those PIDs
        socket_inodes: set[str] = set()
        for p in all_pids:
            try:
                for fd_link in glob.glob(f"/proc/{p}/fd/*"):
                    try:
                        target = os.readlink(fd_link)
                        if target.startswith("socket:["):
                            socket_inodes.add(target[8:-1])
                    except OSError:
                        pass
            except OSError:
                pass

        if not socket_inodes:
            logger.debug("No socket inodes found for container %s (pid %d) — may need root", container.name, pid)
            return []

        # Cross-reference with /proc/net/tcp|udp to get listening ports
        ports: list[dict] = []
        seen: set[tuple] = set()

        for proto, net_file, listen_state in [
            ("tcp", "/proc/net/tcp",  "0A"),
            ("tcp", "/proc/net/tcp6", "0A"),
            ("udp", "/proc/net/udp",  None),
            ("udp", "/proc/net/udp6", None),
        ]:
            try:
                with open(net_file) as f:
                    for line in f.readlines()[1:]:
                        parts = line.split()
                        if len(parts) < 10:
                            continue
                        if listen_state and parts[3] != listen_state:
                            continue
                        inode = parts[9]
                        if inode not in socket_inodes:
                            continue
                        port = int(parts[1].split(":")[1], 16)
                        if port > 0 and (port, proto) not in seen:
                            seen.add((port, proto))
                            ports.append({"host_port": port, "protocol": proto})
            except OSError:
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
