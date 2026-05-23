import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from state_manager import StateManager


def make_sm():
    return StateManager(db_path=":memory:")


def test_save_and_load():
    sm = make_sm()
    data = {"name": "mycontainer", "ports": [{"host_port": 8080, "protocol": "tcp"}], "policy_ids": [1, 2], "address_obj_name": "amp-sync-mycontainer"}
    sm.save("abc123", data)
    result = sm.load_all()
    assert "abc123" in result
    assert result["abc123"]["name"] == "mycontainer"
    assert result["abc123"]["ports"] == [{"host_port": 8080, "protocol": "tcp"}]
    assert result["abc123"]["policy_ids"] == [1, 2]


def test_get_single():
    sm = make_sm()
    data = {"name": "c1", "ports": [], "policy_ids": [], "address_obj_name": "obj1"}
    sm.save("id1", data)
    assert sm.get("id1")["name"] == "c1"
    assert sm.get("nope") is None


def test_remove():
    sm = make_sm()
    sm.save("id2", {"name": "c2", "ports": [], "policy_ids": [], "address_obj_name": "obj2"})
    sm.remove("id2")
    assert sm.get("id2") is None
    assert sm.load_all() == {}


def test_upsert_overwrites():
    sm = make_sm()
    sm.save("id3", {"name": "old", "ports": [], "policy_ids": [], "address_obj_name": "obj3"})
    sm.save("id3", {"name": "new", "ports": [{"host_port": 9000, "protocol": "udp"}], "policy_ids": [5], "address_obj_name": "obj3-new"})
    entry = sm.get("id3")
    assert entry["name"] == "new"
    assert entry["ports"] == [{"host_port": 9000, "protocol": "udp"}]


def test_remove_nonexistent_is_safe():
    sm = make_sm()
    sm.remove("does-not-exist")  # should not raise
