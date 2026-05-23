import sys
from pathlib import Path
from unittest.mock import MagicMock, call

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from reconciler import Reconciler


def make_reconciler(containers, saved_state, live_policies=None, live_addr_objs=None):
    docker = MagicMock()
    docker.get_running_containers.return_value = containers

    state = MagicMock()
    state.load_all.return_value = saved_state
    state.get.side_effect = lambda cid: saved_state.get(cid)

    fg = MagicMock()
    fg.get_managed_policies.return_value = live_policies or []
    fg.get_managed_address_objects.return_value = live_addr_objs or []
    fg.create_address_object.return_value = {}
    fg.create_policy.return_value = {"results": [{"mkey": 10}]}

    rec = Reconciler(docker_inspector=docker, state_manager=state, fortigate_client=fg)
    return rec, docker, state, fg


# ---------------------------------------------------------------------------
# New container → rules created
# ---------------------------------------------------------------------------

def test_new_container_creates_rules():
    containers = [{"id": "c1", "name": "myapp", "image": "nginx",
                   "ports": [{"host_port": 8080, "protocol": "tcp"}]}]
    rec, _, state, fg = make_reconciler(containers, {})

    stats = rec.reconcile()

    fg.create_address_object.assert_called_once()
    fg.create_policy.assert_called_once()
    state.save.assert_called_once()
    assert stats["added"] == 1
    assert stats["removed"] == 0


# ---------------------------------------------------------------------------
# Rules already exist on FG → nothing recreated
# ---------------------------------------------------------------------------

def test_existing_rules_not_duplicated():
    containers = [{"id": "c1", "name": "myapp", "image": "nginx",
                   "ports": [{"host_port": 8080, "protocol": "tcp"}]}]
    live_policies = [{"name": "amp-sync-myapp-8080-tcp", "policyid": 5,
                      "comments": "[amp-sync]", "dstaddr": [{"name": "amp-sync-myapp"}]}]
    live_addr_objs = [{"name": "amp-sync-myapp", "comment": "[amp-sync]"}]
    saved = {"c1": {"name": "myapp", "ports": [{"host_port": 8080, "protocol": "tcp"}],
                    "policy_ids": [5], "address_obj_name": "amp-sync-myapp"}}

    rec, _, state, fg = make_reconciler(containers, saved, live_policies, live_addr_objs)
    rec.reconcile()

    fg.create_address_object.assert_not_called()
    fg.create_policy.assert_not_called()


# ---------------------------------------------------------------------------
# Deleted instance → orphan rules removed via FG comment tag
# ---------------------------------------------------------------------------

def test_orphan_rules_deleted_when_instance_removed():
    # No running containers, but FG still has rules from a deleted instance
    live_policies = [{"name": "amp-sync-oldapp-8080-tcp", "policyid": 7,
                      "comments": "[amp-sync]", "dstaddr": [{"name": "amp-sync-oldapp"}]}]
    live_addr_objs = [{"name": "amp-sync-oldapp", "comment": "[amp-sync]"}]

    rec, _, state, fg = make_reconciler([], {}, live_policies, live_addr_objs)
    stats = rec.reconcile()

    fg.delete_policy.assert_called_once_with(7)
    fg.delete_address_object.assert_called_once_with("amp-sync-oldapp")
    assert stats["removed"] == 1
    assert stats["added"] == 0


# ---------------------------------------------------------------------------
# Orphan cleanup works even when SQLite state is empty (DB lost)
# ---------------------------------------------------------------------------

def test_orphan_cleaned_up_without_sqlite_state():
    live_policies = [{"name": "amp-sync-ghost-9000-tcp", "policyid": 42,
                      "comments": "[amp-sync]", "dstaddr": [{"name": "amp-sync-ghost"}]}]
    live_addr_objs = [{"name": "amp-sync-ghost", "comment": "[amp-sync]"}]

    # SQLite is empty — simulates DB loss
    rec, _, state, fg = make_reconciler([], {}, live_policies, live_addr_objs)
    stats = rec.reconcile()

    fg.delete_policy.assert_called_once_with(42)
    fg.delete_address_object.assert_called_once_with("amp-sync-ghost")
    assert stats["removed"] == 1


# ---------------------------------------------------------------------------
# Port change → old rules deleted, new rules created
# ---------------------------------------------------------------------------

def test_port_change_rebuilds_rules():
    containers = [{"id": "c1", "name": "myapp", "image": "nginx",
                   "ports": [{"host_port": 9090, "protocol": "tcp"}]}]
    live_policies = [{"name": "amp-sync-myapp-8080-tcp", "policyid": 7,
                      "comments": "[amp-sync]", "dstaddr": [{"name": "amp-sync-myapp"}]}]
    live_addr_objs = [{"name": "amp-sync-myapp", "comment": "[amp-sync]"}]
    saved = {"c1": {"name": "myapp", "ports": [{"host_port": 8080, "protocol": "tcp"}],
                    "policy_ids": [7], "address_obj_name": "amp-sync-myapp"}}

    rec, _, state, fg = make_reconciler(containers, saved, live_policies, live_addr_objs)
    stats = rec.reconcile()

    fg.delete_policy.assert_called_once_with(7)
    fg.delete_address_object.assert_called_once_with("amp-sync-myapp")
    fg.create_address_object.assert_called_once()
    fg.create_policy.assert_called_once()


# ---------------------------------------------------------------------------
# FortiGate error is counted, doesn't crash the loop
# ---------------------------------------------------------------------------

def test_fg_error_counted():
    containers = [{"id": "c1", "name": "myapp", "image": "nginx",
                   "ports": [{"host_port": 8080, "protocol": "tcp"}]}]
    rec, _, state, fg = make_reconciler(containers, {})
    fg.create_address_object.side_effect = Exception("FortiGate unreachable")

    stats = rec.reconcile()

    assert stats["errors"] == 1
    assert stats["added"] == 0
