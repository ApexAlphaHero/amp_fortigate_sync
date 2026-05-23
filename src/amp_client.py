import logging
from typing import Optional

import requests

logger = logging.getLogger(__name__)

_AMP_HEADERS = {
    "Accept": "application/vnd.cubecoders-ampapi",
    "Content-Type": "application/json",
}


class AMPClient:
    def __init__(self, host: str, username: str, password: str):
        self._base = host.rstrip("/")
        self._username = username
        self._password = password
        self._session = requests.Session()
        self._session.headers.update(_AMP_HEADERS)
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
                    "SESSIONID": "",
                },
                timeout=5,
            )
            resp.raise_for_status()
            data = resp.json()
            if not data.get("success"):
                reason = data.get("resultReason") or f"result code {data.get('result')}"
                logger.warning("AMP login failed: %s", reason)
                return False
            session_id = data.get("sessionID")
            if not session_id:
                logger.warning("AMP login succeeded but no sessionID in response")
                return False
            self._session_id = session_id
            logger.info("AMP login successful")
            return True
        except requests.RequestException as e:
            logger.warning("AMP login failed: %s", e)
            return False

    def _post(self, path: str, **kwargs) -> Optional[dict]:
        """All AMP API calls are POST with SESSIONID in the body."""
        if not self._session_id and not self._login():
            return None

        body = kwargs.get("json", {})
        body["SESSIONID"] = self._session_id
        kwargs["json"] = body

        try:
            resp = self._session.post(f"{self._base}{path}", timeout=5, **kwargs)
            if resp.status_code == 401:
                if self._login():
                    body["SESSIONID"] = self._session_id
                    resp = self._session.post(f"{self._base}{path}", timeout=5, **kwargs)
                else:
                    return None
            resp.raise_for_status()
            return resp.json()
        except requests.RequestException as e:
            logger.warning("AMP API request failed: %s", e)
            return None

    def get_instances(self) -> dict[str, dict]:
        """
        Returns a mapping of AMP instance friendly name → metadata dict including ports.
        Falls back to empty dict if AMP is unreachable or login fails.
        """
        data = self._post("/API/ADSModule/GetInstances", json={})
        if data is None:
            return {}

        instances = {}
        for entry in data.get("result", []):
            for instance in entry.get("AvailableInstances", []):
                name = instance.get("FriendlyName") or instance.get("InstanceName")
                if not name:
                    continue
                instances[name] = {
                    "instance_id": instance.get("InstanceID"),
                    "module": instance.get("ModuleName"),
                    "running": instance.get("Running", False),
                    "ports": self._parse_endpoints(instance.get("ApplicationEndpoints", [])),
                }
        return instances

    @staticmethod
    def _parse_endpoints(endpoints: list) -> list[dict]:
        """Parse ApplicationEndpoints into [{host_port, protocol}] dicts."""
        ports = []
        seen = set()
        for ep in endpoints:
            endpoint_str = ep.get("Endpoint", "")
            display = (ep.get("DisplayName") or "").upper()

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
        if instances is None:
            instances = self.get_instances()
        for amp_name in instances:
            if amp_name.lower() in container_name.lower() or container_name.lower() in amp_name.lower():
                return amp_name
        return container_name
