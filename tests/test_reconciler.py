import sys
from pathlib import Path
from unittest.mock import MagicMock, call

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from reconciler import Reconciler


def make_reconciler(containers, saved_state, fg_create_policy_result=None):
    docker = MagicMock()
    docker.get_running_containers.return_value = containers

    state = MagicMock()
    state.load_all.return_value = saved_state

    fg = MagicMock()
    fg.create_address_object.return_value = {}
    fg.create_policy.return_value = fg_create_policy_result or {"results": [{"mkey": 10}]}

    return Reconciler(
        docker_inspector=docker,
        state_manager=state,
        fortigate_client=fg,
    ), docker, state, fg


def test_new_container_creates_rules():
    containers = [{"id": "c1", "name": "myapp", "image": "nginx", "ports": [{"host_port": 8080, "protocol": "tcp"}]}]
    rec, docker, state, fg = make_reconciler(containers, {})

    stats = rec.reconcile()

    fg.create_address_object.assert_called_once()
    fg.create_policy.assert_called_once()
    state.save.assert_called_once()
    assert stats["added"] == 1
    assert stats["removed"] == 0


def test_removed_container_deletes_rules():
    saved = {
        "c1": {
            "name": "myapp",
            "ports": [{"host_port": 8080, "protocol": "tcp"}],
            "policy_ids": [42],
            "address_obj_name": "amp-sync-myapp",
        }
    }
    rec, docker, state, fg = make_reconciler([], saved)

    stats = rec.reconcile()

    fg.delete_policy.assert_called_once_with(42)
    fg.delete_address_object.assert_called_once_with("amp-sync-myapp")
    state.remove.assert_called_once_with("c1")
    assert stats["removed"] == 1
    assert stats["added"] == 0


def test_changed_ports_updates_rules():
    containers = [{"id": "c1", "name": "myapp", "image": "nginx", "ports": [{"host_port": 9090, "protocol": "tcp"}]}]
    saved = {
        "c1": {
            "name": "myapp",
            "ports": [{"host_port": 8080, "protocol": "tcp"}],
            "policy_ids": [7],
            "address_obj_name": "amp-sync-myapp",
        }
    }
    rec, docker, state, fg = make_reconciler(containers, saved)

    stats = rec.reconcile()

    fg.delete_policy.assert_called_once_with(7)
    fg.delete_address_object.assert_called_once_with("amp-sync-myapp")
    fg.create_address_object.assert_called_once()
    fg.create_policy.assert_called_once()
    assert stats["updated"] == 1


def test_unchanged_container_does_nothing():
    ports = [{"host_port": 8080, "protocol": "tcp"}]
    containers = [{"id": "c1", "name": "myapp", "image": "nginx", "ports": ports}]
    saved = {
        "c1": {
            "name": "myapp",
            "ports": ports,
            "policy_ids": [3],
            "address_obj_name": "amp-sync-myapp",
        }
    }
    rec, docker, state, fg = make_reconciler(containers, saved)

    stats = rec.reconcile()

    fg.create_address_object.assert_not_called()
    fg.delete_policy.assert_not_called()
    assert stats["added"] == 0
    assert stats["removed"] == 0
    assert stats["updated"] == 0


def test_fg_error_is_counted():
    containers = [{"id": "c1", "name": "myapp", "image": "nginx", "ports": [{"host_port": 8080, "protocol": "tcp"}]}]
    rec, docker, state, fg = make_reconciler(containers, {})
    fg.create_address_object.side_effect = Exception("FortiGate down")

    stats = rec.reconcile()

    assert stats["errors"] == 1
    assert stats["added"] == 0
