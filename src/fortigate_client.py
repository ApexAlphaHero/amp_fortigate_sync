import logging
import time
import urllib3
from typing import Optional

import requests

logger = logging.getLogger(__name__)

_NAME_PREFIX = "amp-sync-"
_MAX_RETRIES = 3
_BACKOFF_BASE = 2.0


class FortigateClient:
    def __init__(self, host: str, token: str, ssl_verify: bool = True, vdom: Optional[str] = None):
        self._base = host.rstrip("/")
        self._verify = ssl_verify
        self._vdom = vdom
        self._session = requests.Session()
        self._session.headers["Authorization"] = f"Bearer {token}"
        if not ssl_verify:
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _url(self, path: str) -> str:
        return f"{self._base}{path}"

    def _request(self, method: str, path: str, **kwargs) -> dict:
        url = self._url(path)
        params = kwargs.pop("params", {})
        if self._vdom:
            params = {**params, "vdom": self._vdom}
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
                    body = ""
                    if hasattr(e, "response") and e.response is not None:
                        try:
                            body = f" — response: {e.response.text[:500]}"
                        except Exception:
                            pass
                    logger.error("FortiGate request failed (final attempt): %s%s", e, body)
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
        return [v for v in data.get("results", []) if (v.get("name") or "").startswith(_NAME_PREFIX)]

    def create_vip(
        self,
        name: str,
        ext_ip: str,
        ext_port: str,
        mapped_ip: str,
        mapped_port: str,
        protocol: str,
    ) -> dict:
        payload = {
            "name": name,
            "type": "static-nat",
            "extip": ext_ip,
            "extintf": "any",
            "portforward": "enable",
            "protocol": protocol.lower(),
            "extport": ext_port,
            "mappedip": [{"range": mapped_ip}],
            "mappedport": mapped_port,
        }
        logger.info("Creating VIP: %s  %s:%s → %s:%s/%s", name, ext_ip, ext_port, mapped_ip, mapped_port, protocol)
        return self._request("POST", "/api/v2/cmdb/firewall/vip/", json=payload)

    def delete_vip(self, name: str):
        logger.info("Deleting VIP: %s", name)
        self._delete(f"/api/v2/cmdb/firewall/vip/{name}", f"VIP {name}")

    # ------------------------------------------------------------------
    # Service objects
    # ------------------------------------------------------------------

    def get_managed_service_objects(self) -> list[dict]:
        data = self._request("GET", "/api/v2/cmdb/firewall.service/custom/")
        return [s for s in data.get("results", []) if (s.get("name") or "").startswith(_NAME_PREFIX)]

    def get_service_categories(self) -> list[dict]:
        data = self._request("GET", "/api/v2/cmdb/firewall.service/category/")
        return data.get("results", [])

    def ensure_service_category(self, name: str):
        """Create the named service category if it doesn't already exist."""
        try:
            cats = self.get_service_categories()
            if any(c.get("name") == name for c in cats):
                logger.debug("Service category %r already exists", name)
                return
            logger.info("Creating service category: %s", name)
            self._request("POST", "/api/v2/cmdb/firewall.service/category/", json={"name": name})
        except Exception as e:
            logger.warning("Could not ensure service category %r: %s", name, e)

    def _service_payload(
        self,
        tcp_ranges: list[str],
        udp_ranges: list[str],
        category: Optional[str],
    ) -> dict:
        payload: dict = {"protocol": "TCP/UDP/UDP-Lite/SCTP"}
        if tcp_ranges:
            payload["tcp-portrange"] = " ".join(tcp_ranges)
        if udp_ranges:
            payload["udp-portrange"] = " ".join(udp_ranges)
        if category:
            payload["category"] = category
        return payload

    def create_service_object(
        self,
        name: str,
        tcp_ranges: list[str],
        udp_ranges: list[str],
        category: Optional[str] = None,
    ) -> dict:
        payload = {"name": name, **self._service_payload(tcp_ranges, udp_ranges, category)}
        logger.info("Creating service object: %s  tcp=%s udp=%s", name, tcp_ranges, udp_ranges)
        return self._request("POST", "/api/v2/cmdb/firewall.service/custom/", json=payload)

    def update_service_object(
        self,
        name: str,
        tcp_ranges: list[str],
        udp_ranges: list[str],
        category: Optional[str] = None,
    ):
        payload = self._service_payload(tcp_ranges, udp_ranges, category)
        logger.info("Updating service object: %s  tcp=%s udp=%s", name, tcp_ranges, udp_ranges)
        self._request("PUT", f"/api/v2/cmdb/firewall.service/custom/{name}", json=payload)

    def delete_service_object(self, name: str):
        logger.info("Deleting service object: %s", name)
        self._delete(f"/api/v2/cmdb/firewall.service/custom/{name}", f"service {name}")

    # ------------------------------------------------------------------
    # Policies
    # ------------------------------------------------------------------

    def get_managed_policies(self) -> list[dict]:
        data = self._request("GET", "/api/v2/cmdb/firewall/policy/")
        return [p for p in data.get("results", []) if (p.get("name") or "").startswith(_NAME_PREFIX)]

    def create_policy(
        self,
        name: str,
        vip_names: list[str],
        service_obj_names: list[str],
        status: str = "enable",
        ssl_ssh_profile: Optional[str] = None,
        dstintf: str = "any",
        srcaddr: Optional[list[str]] = None,
    ) -> dict:
        payload = {
            "name": name,
            "srcintf": [{"name": "any"}],
            "dstintf": [{"name": dstintf}],
            "srcaddr": [{"name": n} for n in (srcaddr or ["all"])],
            "dstaddr": [{"name": n} for n in vip_names],
            "service": [{"name": n} for n in service_obj_names],
            "schedule": "always",
            "action": "accept",
            "status": status,
        }
        if ssl_ssh_profile:
            payload["ssl-ssh-profile"] = ssl_ssh_profile
            payload["inspection-mode"] = "flow"
        logger.info("Creating policy: %s (vips=%s, status=%s)", name, vip_names, status)
        return self._request("POST", "/api/v2/cmdb/firewall/policy/", json=payload)

    def update_policy(self, policy_id: int, vip_names: list[str], service_obj_names: list[str], status: str):
        logger.info("Updating policy %s (vips=%s, status=%s)", policy_id, vip_names, status)
        self._request("PUT", f"/api/v2/cmdb/firewall/policy/{policy_id}", json={
            "dstaddr": [{"name": n} for n in vip_names],
            "service": [{"name": n} for n in service_obj_names],
            "status": status,
        })

    def move_policy_after(self, policy_id: int, after_id: int):
        """Move a policy to sit immediately after another policy in the list."""
        logger.info("Moving policy %s to after policy %s", policy_id, after_id)
        try:
            self._request(
                "PUT",
                f"/api/v2/cmdb/firewall/policy/{policy_id}",
                params={"action": "move", "where": "after", "neighbor": str(after_id)},
                json={},
            )
        except requests.HTTPError as e:
            if e.response is not None and e.response.status_code == 400:
                logger.warning("Policy %s move returned 400 — already in position", policy_id)
            else:
                raise

    def delete_policy(self, policy_id: int):
        logger.info("Deleting policy id: %s", policy_id)
        self._delete(f"/api/v2/cmdb/firewall/policy/{policy_id}", f"policy {policy_id}")
