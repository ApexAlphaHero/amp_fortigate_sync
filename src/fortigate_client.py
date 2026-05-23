import logging
import time
import urllib3
from typing import Optional

import requests

logger = logging.getLogger(__name__)

_SYNC_TAG = "[amp-sync]"
_MAX_RETRIES = 3
_BACKOFF_BASE = 2.0


class FortigateClient:
    def __init__(self, host: str, token: str, ssl_verify: bool = True):
        self._base = host.rstrip("/")
        self._token = token
        self._verify = ssl_verify
        self._session = requests.Session()
        if not ssl_verify:
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _url(self, path: str) -> str:
        return f"{self._base}{path}"

    def _request(self, method: str, path: str, **kwargs) -> dict:
        url = self._url(path)
        # FortiGate REST API expects the token as a query parameter
        params = kwargs.pop("params", {})
        params["access_token"] = self._token
        for attempt in range(_MAX_RETRIES):
            try:
                resp = self._session.request(
                    method, url, verify=self._verify, timeout=15,
                    params=params, **kwargs,
                )
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

    def _delete(self, path: str, label: str):
        """DELETE with silent 404 handling."""
        try:
            self._request("DELETE", path)
        except requests.HTTPError as e:
            if e.response is not None and e.response.status_code == 404:
                logger.debug("%s already gone", label)
            else:
                raise

    # ------------------------------------------------------------------
    # Virtual IPs  (DNAT / port forwarding)
    # ------------------------------------------------------------------

    def get_managed_vips(self) -> list[dict]:
        data = self._request("GET", "/api/v2/cmdb/firewall/vip/")
        return [v for v in data.get("results", []) if _SYNC_TAG in (v.get("comment") or "")]

    def create_vip(
        self,
        name: str,
        ext_ip: str,
        ext_port: int,
        mapped_ip: str,
        mapped_port: int,
        protocol: str,
    ) -> dict:
        payload = {
            "name": name,
            "type": "static-nat",
            "extip": ext_ip,
            "extintf": "any",
            "portforward": "enable",
            "protocol": protocol.lower(),
            "extport": str(ext_port),
            "mappedip": [{"range": mapped_ip}],
            "mappedport": str(mapped_port),
            "comment": _SYNC_TAG,
        }
        logger.info("Creating VIP: %s  %s:%d → %s:%d/%s", name, ext_ip, ext_port, mapped_ip, mapped_port, protocol)
        return self._request("POST", "/api/v2/cmdb/firewall/vip/", json=payload)

    def delete_vip(self, name: str):
        logger.info("Deleting VIP: %s", name)
        self._delete(f"/api/v2/cmdb/firewall/vip/{name}", f"VIP {name}")

    # ------------------------------------------------------------------
    # Service objects
    # ------------------------------------------------------------------

    def get_managed_service_objects(self) -> list[dict]:
        data = self._request("GET", "/api/v2/cmdb/firewall.service/custom/")
        return [s for s in data.get("results", []) if _SYNC_TAG in (s.get("comment") or "")]

    def create_service_object(self, name: str, port: int, protocol: str) -> dict:
        proto_upper = protocol.upper()
        port_str = str(port)
        payload = {
            "name": name,
            "protocol": "TCP/UDP/SCTP",
            "comment": _SYNC_TAG,
        }
        if proto_upper == "UDP":
            payload["udp-portrange"] = port_str
        else:
            payload["tcp-portrange"] = port_str
        logger.info("Creating service object: %s  port %d/%s", name, port, protocol)
        return self._request("POST", "/api/v2/cmdb/firewall.service/custom/", json=payload)

    def delete_service_object(self, name: str):
        logger.info("Deleting service object: %s", name)
        self._delete(f"/api/v2/cmdb/firewall.service/custom/{name}", f"service {name}")

    # ------------------------------------------------------------------
    # Policies
    # ------------------------------------------------------------------

    def get_managed_policies(self) -> list[dict]:
        data = self._request("GET", "/api/v2/cmdb/firewall/policy/")
        return [p for p in data.get("results", []) if _SYNC_TAG in (p.get("comments") or "")]

    def create_policy(
        self,
        name: str,
        vip_name: str,
        service_obj_name: str,
    ) -> dict:
        srcintf = [{"name": "any"}]
        payload = {
            "name": name,
            "srcintf": srcintf,
            "dstintf": [{"name": "any"}],
            "srcaddr": [{"name": "all"}],
            "dstaddr": [{"name": vip_name}],
            "service": [{"name": service_obj_name}],
            "action": "accept",
            "status": "enable",
            "comments": _SYNC_TAG,
        }
        logger.info("Creating policy: %s (vip=%s, svc=%s)", name, vip_name, service_obj_name)
        return self._request("POST", "/api/v2/cmdb/firewall/policy/", json=payload)

    def delete_policy(self, policy_id: int):
        logger.info("Deleting policy id: %s", policy_id)
        self._delete(f"/api/v2/cmdb/firewall/policy/{policy_id}", f"policy {policy_id}")
