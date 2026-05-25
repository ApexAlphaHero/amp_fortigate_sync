import logging
from typing import Optional

import requests

logger = logging.getLogger(__name__)

_SKIP_ENDPOINTS = {"SFTP SERVER"}


class AMPClient:
    def __init__(self, host: str, username: str, password: str):
        self._base = host.rstrip("/")
        self._username = username
        self._password = password
        self._session = requests.Session()
        self._session.headers.update({
            "Accept": "application/json",
            "Content-Type": "application/json",
        })
        self._session_id: Optional[str] = None

    def _login(self) -> bool:
        try:
            resp = self._session.post(
                f"{self._base}/API/Core/Login",
                json={
                    "username": self._username,
                    "password": self._password,
                    "token": "",
                    "rememberMe": False,
                },
                timeout=5,
            )
            resp.raise_for_status()
            data = resp.json()
            session_id = data.get("sessionID")
            if not session_id:
                reason = data.get("resultReason") or f"result code {data.get('result')}"
                logger.warning("AMP login failed: %s", reason)
                return False
            self._session_id = session_id
            self._session.headers["Authorization"] = f"Bearer {session_id}"
            logger.info("AMP login successful")
            return True
        except requests.RequestException as e:
            logger.warning("AMP login failed: %s", e)
            return False

    def _post(self, path: str, params: Optional[dict] = None) -> Optional[dict]:
        """All AMP API calls are POST; session ID is sent as Bearer token."""
        if not self._session_id and not self._login():
            return None

        try:
            resp = self._session.post(
                f"{self._base}{path}",
                json={"parameters": params or {}},
                timeout=5,
            )
            if resp.status_code == 401:
                if self._login():
                    resp = self._session.post(
                        f"{self._base}{path}",
                        json={"parameters": params or {}},
                        timeout=5,
                    )
                else:
                    return None
            resp.raise_for_status()
            return resp.json()
        except requests.RequestException as e:
            logger.warning("AMP API request failed: %s", e)
            return None

    def get_instances(self) -> dict[str, dict]:
        """Returns a mapping of AMP InstanceName → metadata dict including ports.

        Keyed by InstanceName (unique) rather than FriendlyName (may collide).
        """
        data = self._post("/API/ADSModule/GetInstances")
        if data is None:
            return {}

        instances = {}
        entries = data if isinstance(data, list) else data.get("result", [])
        for entry in entries:
            for instance in entry.get("AvailableInstances", []):
                name = instance.get("InstanceName")
                if not name:
                    continue
                module = instance.get("ModuleName", "")
                # Skip the ADS controller itself — it's not a game server
                if module == "ADS":
                    continue
                ports = self._parse_endpoints(instance.get("ApplicationEndpoints", []))
                instances[name] = {
                    "instance_id": instance.get("InstanceID"),
                    "module": module,
                    "friendly_name": instance.get("FriendlyName"),
                    "running": instance.get("Running", False),
                    "ports": ports,
                }
        return instances

    @staticmethod
    def _parse_endpoints(endpoints: list) -> list[dict]:
        """Parse ApplicationEndpoints into [{host_port, protocol}] dicts.

        Skips SFTP and other non-game endpoints.
        Defaults to UDP when the display name doesn't specify a protocol,
        which is correct for the majority of game servers.
        """
        ports = []
        seen = set()
        for ep in endpoints:
            display = (ep.get("DisplayName") or "").upper()
            if display in _SKIP_ENDPOINTS:
                continue

            endpoint_str = ep.get("Endpoint", "")
            if ":" in endpoint_str:
                _, port_str = endpoint_str.rsplit(":", 1)
            else:
                port_str = endpoint_str

            try:
                port = int(port_str)
            except ValueError:
                continue

            proto = "tcp" if "TCP" in display else "udp"
            key = (port, proto)
            if key not in seen:
                seen.add(key)
                ports.append({"host_port": port, "protocol": proto})
        return ports

    def resolve_container_name(self, container_name: str, instances: Optional[dict] = None) -> str:
        """Map a Docker container name to its AMP InstanceName.

        Docker containers are typically named AMP_{InstanceName}, so we try
        stripping that prefix first before falling back to substring matching.
        """
        if instances is None:
            instances = self.get_instances()

        # Exact match after stripping the AMP_ prefix
        clean = container_name.removeprefix("AMP_")
        if clean in instances:
            return clean

        # Fallback: substring match (handles non-standard naming)
        for instance_name in instances:
            if instance_name.lower() in container_name.lower():
                return instance_name

        return container_name
