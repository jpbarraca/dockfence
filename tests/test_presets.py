"""Preset catalog + apply/delete semantics (anti-exfiltration hardening)."""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest

from dockfence import presets
from dockfence.store import Store


@pytest.fixture
def store(tmp_path):
    return Store(str(tmp_path / "presets.db"))


def test_catalog_is_valid():
    """Catalog rules are validated at import; assert the exfil-relevant shape."""
    assert "deny-private-out" in presets.CATALOG
    assert "harden-egress" in presets.CATALOG
    assert presets.CATALOG["harden-egress"]["compose"][-1] == "deny-private-out"
    for spec in presets.CATALOG.values():
        for r in spec["rules"]:
            assert r["direction"] == "out"
            assert r["action"] in ("accept", "drop")
    for r in presets.CATALOG["deny-private-out"]["rules"]:
        assert r["action"] == "drop" and r["log"] is True


def test_dns_out_idempotent(store):
    pid = store.get_or_create_policy("web")
    first = presets.apply_preset(store, pid, "dns-out")
    assert len(first["added"]) == 2 and first["skipped"] == 0
    second = presets.apply_preset(store, pid, "dns-out")
    assert second["added"] == [] and second["skipped"] == 2
    assert len(store.list_rules(pid)) == 2


def test_deny_private_front_placement(store):
    """Deny rules must sort BEFORE existing broad allows (first-match-wins)."""
    pid = store.get_or_create_policy("web")
    presets.apply_preset(store, pid, "web-out")
    presets.apply_preset(store, pid, "deny-private-out")
    rules = store.list_rules(pid)
    denies = [r for r in rules if r.action == "drop"]
    allows = [r for r in rules if r.action == "accept"]
    assert len(denies) == 9
    assert max(r.position for r in denies) < min(r.position for r in allows)


def test_deny_private_covers_private_ranges(store):
    pid = store.get_or_create_policy("web")
    presets.apply_preset(store, pid, "deny-private-out")
    cidrs = {r.cidr for r in store.list_rules(pid)}
    assert {"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
            "127.0.0.0/8", "100.64.0.0/10", "fc00::/7", "::1/128"} <= cidrs
    for r in store.list_rules(pid):
        assert r.direction == "out" and r.log is True


def test_harden_egress_composite(store):
    pid = store.get_or_create_policy("web")
    res = presets.apply_preset(store, pid, "harden-egress")
    # dns 2 + ntp 1 + web 2 + icmp 1 + deny-private 9
    assert len(res["added"]) == 15 and res["skipped"] == 0
    rules = store.list_rules(pid)
    assert len(rules) == 15
    denies = [r for r in rules if r.action == "drop"]
    allows = [r for r in rules if r.action == "accept"]
    assert len(denies) == 9 and len(allows) == 6
    assert max(r.position for r in denies) < min(r.position for r in allows)
    # composite is idempotent too
    again = presets.apply_preset(store, pid, "harden-egress")
    assert again["added"] == [] and again["skipped"] == 15


def test_delete_preset_removes_rules(store):
    pid = store.get_or_create_policy("web")
    presets.apply_preset(store, pid, "dns-out")
    assert presets.delete_preset(store, pid, "dns-out") == 2
    assert store.list_rules(pid) == []
    assert presets.delete_preset(store, pid, "dns-out") == 0


def test_delete_preset_keeps_foreign_rules(store):
    """Only rules identical to the preset's are removed — user rules survive."""
    pid = store.get_or_create_policy("web")
    presets.apply_preset(store, pid, "dns-out")
    store.add_rule(pid, {"direction": "out", "proto": "udp", "port": 53,
                         "cidr": "10.0.0.1/32", "action": "accept"})
    assert presets.delete_preset(store, pid, "dns-out") == 2
    assert len(store.list_rules(pid)) == 1


def test_delete_composite_removes_all(store):
    pid = store.get_or_create_policy("web")
    presets.apply_preset(store, pid, "harden-egress")
    assert presets.delete_preset(store, pid, "harden-egress") == 15
    assert store.list_rules(pid) == []


def test_unknown_preset_raises(store):
    pid = store.get_or_create_policy("web")
    with pytest.raises(KeyError):
        presets.apply_preset(store, pid, "nope")
    with pytest.raises(KeyError):
        presets.delete_preset(store, pid, "nope")


def test_add_rule_honors_position_zero(store):
    """Regression: explicit position 0 must not fall back to MAX+1."""
    pid = store.get_or_create_policy("web")
    rid = store.add_rule(pid, {"direction": "out", "proto": "any",
                               "action": "drop", "position": 0})
    assert store.get_rule(rid).position == 0
    rid2 = store.add_rule(pid, {"direction": "out", "proto": "any", "action": "accept"})
    assert store.get_rule(rid2).position == 1  # appended after
