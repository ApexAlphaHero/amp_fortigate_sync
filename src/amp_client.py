import logging
from typing import Optional

import requests

logger = logging.getLogger(__name__)


class AMPClient:
    def __init__(self, host: str, username: str, password: str):
        self._base = host.rstrip("/")
        self._username = username
        self._password = password
        self._session = requests.Session()
        self._session_id: Optional[str] = None

    def _login(self) -> bool:
        try:
            resp = self._session.post(
                f"{self._base}/API/Core/Login",
                json={"username": self._username, "password": self._password, "token": "", "rememberMe": False},
                timeout=5,
            )
            resp.raise_for_status()
            data = resp.json()
            session_id = data.get("sessionID") or (data.get("result") or {}).get("sessionID")
            if not session_id:
                logger.warning("AMP login succeeded but no sessionID in response")
                return False
            self._session_id = session_id
            return True
        except requests.RequestException as e:
            logger.warning("AMP login failed: %s", e)
            return False

    def _get(self, path: str) -> Optional[dict]:
        if not self._session_id and not self._login():
            return None
        try:
            resp = self._session.get(
                f"{self._base}{path}",
                params={"SESSIONID": self._session_id},
                timeout=5,
            )
            if resp.status_code == 401:
                # Session expired — re-login once
                if self._login():
                    resp = self._session.get(
                        f"{self._base}{path}",
                        params={"SESSIONID": self._session_id},
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
        """
        Returns a mapping of AMP instance friendly name → metadata dict.
        Falls back to empty dict if AMP is unreachable or login fails.
        """
        data = self._get("/API/ADSModule/GetInstances")
        if data is None:
            return {}

        instances = {}
        for entry in data.get("result", []):
            for instance in entry.get("AvailableInstances", []):
                name = instance.get("FriendlyName") or instance.get("InstanceName")
                if name:
                    instances[name] = {
                        "instance_id": instance.get("InstanceID"),
                        "module": instance.get("ModuleName"),
                        "running": instance.get("Running", False),
                    }
        return instances

    def resolve_container_name(self, container_name: str, instances: Optional[dict] = None) -> str:
        """
        Returns the AMP friendly name for a container if one can be matched,
        otherwise returns the container name unchanged.
        """
        if instances is None:
            instances = self.get_instances()
        for amp_name in instances:
            if amp_name.lower() in container_name.lower() or container_name.lower() in amp_name.lower():
                return amp_name
        return container_name
