import logging
import time
from typing import Optional

import requests
import requests.adapters

logger = logging.getLogger(__name__)

_SYNC_TAG = "[amp-sync]"
_MAX_RETRIES = 3
_BACKOFF_BASE = 2.0


class FortigateClient:
    def __init__(self, host: str, token: str, ssl_verify: bool = True):
        self._base = host.rstrip("/")
        self._verify = ssl_verify
        self._session = requests.Session()
        self._session.headers.update({"Authorization": f"Bearer {token}"})

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _url(self, path: str) -> str:
        return f"{self._base}{path}"

    def _request(self, method: str, path: str, **kwargs) -> dict:
        url = self._url(path)
        for attempt in range(_MAX_RETRIES):
            try:
                resp = self._session.request(method, url, verify=self._verify, timeout=15, **kwargs)
                resp.raise_for_status()
                return resp.json() if resp.content else {}
            except requests.RequestException as e:
                if attempt == _MAX_RETRIES - 1:
                    raise
                wait = _BACKOFF_BASE ** attempt
                logger.warning("FortiGate request failed (attempt %d/%d): %s — retrying in %.1fs",
                               attempt + 1, _MAX_RETRIES, e, wait)
                time.sleep(wait)
        return {}  # unreachable

    # ------------------------------------------------------------------
    # Address objects
    # ------------------------------------------------------------------

    def create_address_object(self, name: str, ip: str) -> dict:
        payload = {
            "name": name,
            "type": "ipmask",
            "subnet": f"{ip}/32",
            "comment": _SYNC_TAG,
        }
        logger.info("Creating FortiGate address object: %s → %s", name, ip)
        return self._request("POST", "/api/v2/cmdb/firewall/address/", json=payload)

    def delete_address_object(self, name: str):
        logger.info("Deleting FortiGate address object: %s", name)
        try:
            self._request("DELETE", f"/api/v2/cmdb/firewall/address/{name}")
        except requests.HTTPError as e:
            if e.response is not None and e.response.status_code == 404:
                logger.debug("Address object %s already gone", name)
            else:
                raise

    # ------------------------------------------------------------------
    # Policies
    # ------------------------------------------------------------------

    def get_managed_address_objects(self) -> list[dict]:
        data = self._request("GET", "/api/v2/cmdb/firewall/address/")
        results = data.get("results", [])
        return [a for a in results if _SYNC_TAG in (a.get("comment") or "")]

    def get_managed_policies(self) -> list[dict]:
        data = self._request("GET", "/api/v2/cmdb/firewall/policy/")
        results = data.get("results", [])
        return [p for p in results if _SYNC_TAG in (p.get("comments") or "")]

    def create_policy(
        self,
        name: str,
        port: int,
        protocol: str,
        address_obj_name: str,
        interfaces: Optional[list[str]] = None,
    ) -> dict:
        srcintf = [{"name": iface} for iface in (interfaces or ["port1"])]
        service_name = f"TCP_{port}" if protocol.lower() == "tcp" else f"UDP_{port}"
        payload = {
            "name": name,
            "srcintf": srcintf,
            "dstintf": [{"name": "any"}],
            "srcaddr": [{"name": "all"}],
            "dstaddr": [{"name": address_obj_name}],
            "service": [{"name": service_name}],
            "action": "accept",
            "status": "enable",
            "comments": _SYNC_TAG,
        }
        logger.info("Creating FortiGate policy: %s (port %d/%s)", name, port, protocol)
        return self._request("POST", "/api/v2/cmdb/firewall/policy/", json=payload)

    def delete_policy(self, policy_id: int):
        logger.info("Deleting FortiGate policy id: %s", policy_id)
        try:
            self._request("DELETE", f"/api/v2/cmdb/firewall/policy/{policy_id}")
        except requests.HTTPError as e:
            if e.response is not None and e.response.status_code == 404:
                logger.debug("Policy %s already gone", policy_id)
            else:
                raise
