import sys
from pathlib import Path
from unittest.mock import MagicMock

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from reconciler import Reconciler

EXT_IP = "1.2.3.4"


def make_reconciler(containers, saved_state, live_vips=None, live_services=None, live_policies=None):
    docker = MagicMock()
    docker.get_running_containers.return_value = containers

    state = MagicMock()
    state.load_all.return_value = saved_state
    state.get.side_effect = lambda cid: saved_state.get(cid)

    fg = MagicMock()
    fg.get_managed_vips.return_value = live_vips or []
    fg.get_managed_service_objects.return_value = live_services or []
    fg.get_managed_policies.return_value = live_policies or []
    fg.create_vip.return_value = {}
    fg.create_service_object.return_value = {}
    fg.create_policy.return_value = {"results": [{"mkey": 10}]}

    rec = Reconciler(
        docker_inspector=docker,
        state_manager=state,
        fortigate_client=fg,
        ext_ip=EXT_IP,
    )
    return rec, docker, state, fg


# ---------------------------------------------------------------------------
# New container → VIP + service + policy created
# ---------------------------------------------------------------------------

def test_new_container_creates_all_three_objects():
    containers = [{"id": "c1", "name": "myapp", "image": "nginx",
                   "ports": [{"host_port": 8080, "protocol": "tcp"}]}]
    rec, _, state, fg = make_reconciler(containers, {})

    stats = rec.reconcile()

    fg.create_vip.assert_called_once()
    vip_call = fg.create_vip.call_args
    assert vip_call.kwargs["ext_ip"] == EXT_IP
    assert vip_call.kwargs["ext_port"] == 8080
    assert vip_call.kwargs["protocol"] == "tcp"

    fg.create_service_object.assert_called_once()
    svc_call = fg.create_service_object.call_args
    assert svc_call.kwargs["port"] == 8080
    assert svc_call.kwargs["protocol"] == "tcp"

    fg.create_policy.assert_called_once()
    state.save.assert_called_once()
    assert stats["added"] == 1
    assert stats["removed"] == 0


# ---------------------------------------------------------------------------
# Objects already exist on FG → nothing recreated
# ---------------------------------------------------------------------------

def test_existing_objects_not_duplicated():
    containers = [{"id": "c1", "name": "myapp", "image": "nginx",
                   "ports": [{"host_port": 8080, "protocol": "tcp"}]}]
    name = "amp-sync-myapp-8080-tcp"
    live_vips = [{"name": name, "comment": "[amp-sync]"}]
    live_services = [{"name": name, "comment": "[amp-sync]"}]
    live_policies = [{"name": name, "policyid": 5, "comments": "[amp-sync]"}]
    saved = {"c1": {"name": "myapp", "ports": [{"host_port": 8080, "protocol": "tcp"}],
                    "policy_ids": [5], "vip_names": [name], "service_obj_names": [name]}}

    rec, _, state, fg = make_reconciler(containers, saved, live_vips, live_services, live_policies)
    rec.reconcile()

    fg.create_vip.assert_not_called()
    fg.create_service_object.assert_not_called()
    fg.create_policy.assert_not_called()


# ---------------------------------------------------------------------------
# Deleted instance → orphan VIP/service/policy removed
# ---------------------------------------------------------------------------

def test_orphan_objects_deleted_when_instance_removed():
    name = "amp-sync-oldapp-8080-tcp"
    live_vips = [{"name": name, "comment": "[amp-sync]"}]
    live_services = [{"name": name, "comment": "[amp-sync]"}]
    live_policies = [{"name": name, "policyid": 7, "comments": "[amp-sync]"}]

    rec, _, state, fg = make_reconciler([], {}, live_vips, live_services, live_policies)
    stats = rec.reconcile()

    fg.delete_policy.assert_called_once_with(7)
    fg.delete_service_object.assert_called_once_with(name)
    fg.delete_vip.assert_called_once_with(name)
    assert stats["removed"] == 1
    assert stats["added"] == 0


# ---------------------------------------------------------------------------
# Orphan cleanup works even when SQLite state is empty (DB wiped)
# ---------------------------------------------------------------------------

def test_orphan_cleaned_up_without_sqlite_state():
    name = "amp-sync-ghost-9000-udp"
    live_vips = [{"name": name, "comment": "[amp-sync]"}]
    live_policies = [{"name": name, "policyid": 42, "comments": "[amp-sync]"}]

    rec, _, state, fg = make_reconciler([], {}, live_vips, [], live_policies)
    stats = rec.reconcile()

    fg.delete_policy.assert_called_once_with(42)
    fg.delete_vip.assert_called_once_with(name)
    assert stats["removed"] == 1


# ---------------------------------------------------------------------------
# Port change → old objects torn down, new ones created
# ---------------------------------------------------------------------------

def test_port_change_rebuilds_all_objects():
    old_name = "amp-sync-myapp-8080-tcp"
    new_port = 9090
    containers = [{"id": "c1", "name": "myapp", "image": "nginx",
                   "ports": [{"host_port": new_port, "protocol": "tcp"}]}]
    live_vips = [{"name": old_name, "comment": "[amp-sync]"}]
    live_services = [{"name": old_name, "comment": "[amp-sync]"}]
    live_policies = [{"name": old_name, "policyid": 7, "comments": "[amp-sync]"}]
    saved = {"c1": {"name": "myapp", "ports": [{"host_port": 8080, "protocol": "tcp"}],
                    "policy_ids": [7], "vip_names": [old_name], "service_obj_names": [old_name]}}

    rec, _, state, fg = make_reconciler(containers, saved, live_vips, live_services, live_policies)
    rec.reconcile()

    fg.delete_policy.assert_called_once_with(7)
    fg.delete_service_object.assert_called_once_with(old_name)
    fg.delete_vip.assert_called_once_with(old_name)
    fg.create_vip.assert_called_once()
    fg.create_service_object.assert_called_once()
    fg.create_policy.assert_called_once()


# ---------------------------------------------------------------------------
# FortiGate error is counted without crashing the loop
# ---------------------------------------------------------------------------

def test_fg_error_counted():
    containers = [{"id": "c1", "name": "myapp", "image": "nginx",
                   "ports": [{"host_port": 8080, "protocol": "tcp"}]}]
    rec, _, state, fg = make_reconciler(containers, {})
    fg.create_vip.side_effect = Exception("FortiGate unreachable")

    stats = rec.reconcile()

    assert stats["errors"] == 1
    assert stats["added"] == 0
