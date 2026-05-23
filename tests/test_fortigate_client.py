import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from fortigate_client import FortigateClient


def make_client():
    return FortigateClient(host="https://fg.example.com", token="test-token", ssl_verify=False)


def _mock_response(json_data=None, status_code=200):
    resp = MagicMock()
    resp.status_code = status_code
    resp.content = b"{}" if json_data is None else b"data"
    resp.json.return_value = json_data or {}
    resp.raise_for_status = MagicMock()
    return resp


# ---------------------------------------------------------------------------
# VIPs
# ---------------------------------------------------------------------------

@patch("fortigate_client.requests.Session")
def test_create_vip(mock_session_cls):
    mock_session = MagicMock()
    mock_session_cls.return_value = mock_session
    mock_session.request.return_value = _mock_response({})

    client = make_client()
    client.create_vip("amp-sync-myapp-8080-tcp", "1.2.3.4", 8080, "192.168.1.10", 8080, "tcp")

    call = mock_session.request.call_args
    assert call[0][0] == "POST"
    assert "/api/v2/cmdb/firewall/vip/" in call[0][1]
    payload = call[1]["json"]
    assert payload["name"] == "amp-sync-myapp-8080-tcp"
    assert payload["extip"] == "1.2.3.4"
    assert payload["extport"] == "8080"
    assert payload["mappedip"] == [{"range": "192.168.1.10"}]
    assert payload["portforward"] == "enable"
    assert payload["protocol"] == "tcp"
    assert "[amp-sync]" in payload["comment"]


@patch("fortigate_client.requests.Session")
def test_get_managed_vips_filters_by_tag(mock_session_cls):
    mock_session = MagicMock()
    mock_session_cls.return_value = mock_session
    mock_session.request.return_value = _mock_response({
        "results": [
            {"name": "amp-sync-myapp-8080-tcp", "comment": "[amp-sync]"},
            {"name": "manual-vip", "comment": ""},
            {"name": "amp-sync-other-9000-udp", "comment": "[amp-sync] extra"},
        ]
    })

    client = make_client()
    vips = client.get_managed_vips()

    assert len(vips) == 2
    assert all("[amp-sync]" in v["comment"] for v in vips)


@patch("fortigate_client.requests.Session")
def test_delete_vip_404_is_silent(mock_session_cls):
    import requests as req
    mock_session = MagicMock()
    mock_session_cls.return_value = mock_session
    mock_session.request.side_effect = req.HTTPError(response=MagicMock(status_code=404))

    client = make_client()
    client.delete_vip("amp-sync-gone")  # should not raise


# ---------------------------------------------------------------------------
# Service objects
# ---------------------------------------------------------------------------

@patch("fortigate_client.requests.Session")
def test_create_service_object_tcp(mock_session_cls):
    mock_session = MagicMock()
    mock_session_cls.return_value = mock_session
    mock_session.request.return_value = _mock_response({})

    client = make_client()
    client.create_service_object("amp-sync-myapp-8080-tcp", 8080, "tcp")

    payload = mock_session.request.call_args[1]["json"]
    assert payload["name"] == "amp-sync-myapp-8080-tcp"
    assert payload["tcp-portrange"] == "8080"
    assert "udp-portrange" not in payload
    assert "[amp-sync]" in payload["comment"]


@patch("fortigate_client.requests.Session")
def test_create_service_object_udp(mock_session_cls):
    mock_session = MagicMock()
    mock_session_cls.return_value = mock_session
    mock_session.request.return_value = _mock_response({})

    client = make_client()
    client.create_service_object("amp-sync-game-27015-udp", 27015, "udp")

    payload = mock_session.request.call_args[1]["json"]
    assert payload["udp-portrange"] == "27015"
    assert "tcp-portrange" not in payload


@patch("fortigate_client.requests.Session")
def test_get_managed_service_objects_filters_by_tag(mock_session_cls):
    mock_session = MagicMock()
    mock_session_cls.return_value = mock_session
    mock_session.request.return_value = _mock_response({
        "results": [
            {"name": "amp-sync-myapp-8080-tcp", "comment": "[amp-sync]"},
            {"name": "HTTPS", "comment": ""},
        ]
    })

    client = make_client()
    objs = client.get_managed_service_objects()

    assert len(objs) == 1
    assert objs[0]["name"] == "amp-sync-myapp-8080-tcp"


# ---------------------------------------------------------------------------
# Policies
# ---------------------------------------------------------------------------

@patch("fortigate_client.requests.Session")
def test_create_policy_uses_vip_and_service(mock_session_cls):
    mock_session = MagicMock()
    mock_session_cls.return_value = mock_session
    mock_session.request.return_value = _mock_response({"results": [{"mkey": 42}]})

    client = make_client()
    client.create_policy("amp-sync-myapp-8080-tcp", "amp-sync-myapp-8080-tcp", "amp-sync-myapp-8080-tcp")

    payload = mock_session.request.call_args[1]["json"]
    assert payload["dstaddr"] == [{"name": "amp-sync-myapp-8080-tcp"}]
    assert payload["service"] == [{"name": "amp-sync-myapp-8080-tcp"}]
    assert payload["comments"] == "[amp-sync]"


@patch("fortigate_client.requests.Session")
def test_get_managed_policies_filters_by_tag(mock_session_cls):
    mock_session = MagicMock()
    mock_session_cls.return_value = mock_session
    mock_session.request.return_value = _mock_response({
        "results": [
            {"policyid": 1, "name": "amp-sync-a", "comments": "[amp-sync]"},
            {"policyid": 2, "name": "manual",     "comments": ""},
            {"policyid": 3, "name": "amp-sync-b", "comments": "[amp-sync]"},
        ]
    })

    client = make_client()
    policies = client.get_managed_policies()

    assert len(policies) == 2


# ---------------------------------------------------------------------------
# Retry logic
# ---------------------------------------------------------------------------

@patch("fortigate_client.requests.Session")
@patch("fortigate_client.time.sleep")
def test_retry_on_connection_error(mock_sleep, mock_session_cls):
    import requests as req
    mock_session = MagicMock()
    mock_session_cls.return_value = mock_session
    mock_session.request.side_effect = [
        req.ConnectionError("timeout"),
        req.ConnectionError("timeout"),
        _mock_response({}),
    ]

    client = make_client()
    client._request("GET", "/api/v2/cmdb/firewall/policy/")

    assert mock_session.request.call_count == 3
    assert mock_sleep.call_count == 2
