import logging
from typing import Optional

import requests

logger = logging.getLogger(__name__)

# Descriptions containing these words are skipped — not player-facing ports
_SKIP_DESCRIPTIONS = {"SFTP", "RCON"}

# AMP protocol field values
_PROTO_MAP = {0: ["tcp"], 1: ["udp"], 2: ["tcp", "udp"]}


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

    def _post(self, path: str, params: Optional[dict] = None, wrap: bool = True) -> Optional[dict]:
        """All AMP API calls are POST; session ID is sent as Bearer token.

        Most endpoints expect {"parameters": {...}}; pass wrap=False for the
        few that expect a flat body instead.
        """
        if not self._session_id and not self._login():
            return None

        body = {"parameters": params or {}} if wrap else (params or {})
        try:
            resp = self._session.post(f"{self._base}{path}", json=body, timeout=5)
            if resp.status_code == 401:
                if self._login():
                    resp = self._session.post(f"{self._base}{path}", json=body, timeout=5)
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
                if module.upper().startswith("ADS"):
                    continue
                ports = self._get_network_ports(name)
                instances[name] = {
                    "instance_id": instance.get("InstanceID"),
                    "module": module,
                    "friendly_name": instance.get("FriendlyName"),
                    "running": instance.get("Running", False),
                    "ports": ports,
                }
        return instances

    def _get_network_ports(self, instance_name: str) -> list[dict]:
        """Fetch per-instance port list via GetInstanceNetworkInfo.

        Uses IsFirewallTarget to identify ports that need forwarding, and
        the Protocol field for the actual transport (0=TCP, 1=UDP, 2=both).
        SFTP and RCON ports are excluded.
        """
        data = self._post(
            "/API/ADSModule/GetInstanceNetworkInfo",
            {"InstanceName": instance_name},
            wrap=False,
        )
        if not isinstance(data, list):
            logger.warning("GetInstanceNetworkInfo for %s returned unexpected data: %s", instance_name, data)
            return []

        ports = []
        seen: set[tuple] = set()
        for entry in data:
            if not entry.get("IsFirewallTarget"):
                continue
            desc = (entry.get("Description") or "").upper()
            if any(skip in desc for skip in _SKIP_DESCRIPTIONS):
                continue
            port = entry.get("PortNumber")
            if port is None:
                continue
            proto_num = entry.get("Protocol", 0)
            for proto in _PROTO_MAP.get(proto_num, ["tcp"]):
                key = (port, proto)
                if key not in seen:
                    seen.add(key)
                    ports.append({"host_port": port, "protocol": proto, "description": entry.get("Description", "")})
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
