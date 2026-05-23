import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

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


@patch("fortigate_client.requests.Session")
def test_create_address_object(mock_session_cls):
    mock_session = MagicMock()
    mock_session_cls.return_value = mock_session
    mock_session.request.return_value = _mock_response({"results": [{"mkey": 1}]})

    client = make_client()
    client.create_address_object("amp-sync-myapp", "192.168.1.10")

    call_kwargs = mock_session.request.call_args
    assert call_kwargs[0][0] == "POST"
    assert "/api/v2/cmdb/firewall/address/" in call_kwargs[0][1]
    payload = call_kwargs[1]["json"]
    assert payload["name"] == "amp-sync-myapp"
    assert payload["subnet"] == "192.168.1.10/32"
    assert "[amp-sync]" in payload["comment"]


@patch("fortigate_client.requests.Session")
def test_create_policy(mock_session_cls):
    mock_session = MagicMock()
    mock_session_cls.return_value = mock_session
    mock_session.request.return_value = _mock_response({"results": [{"mkey": 42}]})

    client = make_client()
    client.create_policy("amp-sync-myapp-8080", 8080, "tcp", "amp-sync-myapp")

    call_kwargs = mock_session.request.call_args
    assert call_kwargs[0][0] == "POST"
    payload = call_kwargs[1]["json"]
    assert payload["comments"] == "[amp-sync]"
    assert payload["service"] == [{"name": "TCP_8080"}]


@patch("fortigate_client.requests.Session")
def test_get_managed_policies_filters_by_tag(mock_session_cls):
    mock_session = MagicMock()
    mock_session_cls.return_value = mock_session
    mock_session.request.return_value = _mock_response({
        "results": [
            {"policyid": 1, "comments": "[amp-sync] web"},
            {"policyid": 2, "comments": "manual rule"},
            {"policyid": 3, "comments": "[amp-sync]"},
        ]
    })

    client = make_client()
    policies = client.get_managed_policies()

    assert len(policies) == 2
    assert all("[amp-sync]" in p["comments"] for p in policies)


@patch("fortigate_client.requests.Session")
def test_delete_policy_404_is_silent(mock_session_cls):
    import requests as req
    mock_session = MagicMock()
    mock_session_cls.return_value = mock_session
    http_err = req.HTTPError(response=MagicMock(status_code=404))
    mock_session.request.side_effect = http_err

    client = make_client()
    client.delete_policy(99)  # should not raise


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
