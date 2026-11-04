import time

import pytest

from dockfence.store import Store


def test_policy_and_rules(store: Store):
    pid = store.get_or_create_policy("web")
    assert store.get_or_create_policy("web") == pid
    rid = store.add_rule(pid, {"direction": "out", "proto": "tcp", "port": 443,
                               "action": "accept", "cidr": "203.0.113.4/32"})
    rules = store.list_rules(policy_id=pid)
    assert len(rules) == 1
    assert rules[0].port == 443 and rules[0].position == 1

    store.update_rule(rid, {"enabled": False})
    assert store.get_rule(rid).enabled is False
    assert store.delete_rule(rid)
    assert not store.delete_rule(rid)


def test_shared_policy_survives_recreate(store: Store):
    pid = store.get_or_create_policy("web")
    store.add_rule(pid, {"direction": "in", "proto": "tcp", "port": 8080, "action": "accept"})
    # container recreated: same policy name → same rules
    assert len(store.list_rules(policy_id=pid)) == 1


def test_container_upsert(store: Store):
    store.upsert_container({"id": "abc123", "name": "web", "ips": ["172.18.0.5"],
                            "networks": [{"name": "bridge", "v4": "172.18.0.5"}],
                            "state": "running"})
    store.upsert_container({"id": "abc123", "name": "web", "ips": ["172.18.0.6"],
                            "networks": [], "state": "running"})
    c = store.get_container("abc123")
    assert c["ips"] == ["172.18.0.6"]
    assert c["networks"] == []


def test_logs_and_counts(store: Store):
    now = int(time.time())
    for i in range(5):
        store.insert_log({"ts": now - i, "container_id": "c1", "dir": "out",
                          "src": "172.18.0.5", "dst": "1.2.3.4", "proto": "tcp",
                          "sport": 44444, "dport": 443, "family": 4})
    assert store.count_logs("c1", hours=24) == 5
    assert store.blocked_counts(24)["c1"] == 5
    rows = store.query_logs(container_id="c1", direction="out", port=443)
    assert len(rows) == 5
    assert rows[0]["dport"] == 443
    assert store.query_logs(container_id="c1", port=22) == []


def test_retention_by_age(store: Store):
    now = int(time.time())
    store.insert_log({"ts": now, "container_id": "c1"})
    store.insert_log({"ts": now - 100 * 86400, "container_id": "c1"})
    stats = store.prune_retention(days=30, max_rows=0, event_days=7)
    assert stats["logs_age_deleted"] == 1
    assert store.count_logs("c1", hours=24 * 365) == 1


def test_retention_by_size(store: Store):
    for i in range(10):
        store.insert_log({"ts": 1000 + i, "container_id": "c1"})
    stats = store.prune_retention(days=0, max_rows=3, event_days=7)
    assert stats["logs_size_deleted"] == 7
    assert store.query_logs(limit=100) == store.query_logs(limit=100)
    assert len(store.query_logs(limit=100)) == 3
    assert [r["ts"] for r in store.query_logs(limit=100)] == [1009, 1008, 1007]


def test_export_import_roundtrip(store: Store):
    pid = store.get_or_create_policy("web")
    store.add_rule(pid, {"direction": "out", "proto": "udp", "port": 53, "action": "accept"})
    data = store.export_json()
    other = Store(store.path + ".other")
    n = other.import_json(data)
    assert n == 1
    assert other.export_json() == data


def test_corrupt_db_refuses(tmp_path):
    p = tmp_path / "corrupt.db"
    p.write_bytes(b"this is not a database" * 100)
    with pytest.raises(RuntimeError):
        Store(str(p))


def test_settings_default_off_and_roundtrip(store: Store):
    # both toggles default OFF (logging is opt-in)
    assert store.get_bool_setting("logging", False) is False
    assert store.get_bool_setting("dns_log", False) is False
    store.set_settings({"logging": True, "dns_log": False})
    assert store.get_bool_setting("logging") is True
    assert store.get_bool_setting("dns_log") is False
    # visible from a fresh connection on the same file (WAL)
    assert Store(store.path).get_bool_setting("logging") is True


def test_dns_mapping_annotation_and_clear(store: Store):
    store.upsert_dns("github.com", "140.82.121.4", "192.168.1.1", ts=1000)
    store.upsert_dns("github.com", "140.82.121.4", "192.168.1.1", ts=2000)
    rows = store.dns_mappings()
    assert len(rows) == 1
    assert rows[0]["hits"] == 2 and rows[0]["last_seen"] == 2000
    assert rows[0]["first_seen"] == 1000
    assert store.name_for_ip("140.82.121.4") == "github.com"
    assert store.name_for_ip("8.8.8.8") is None
    log_rows = [{"src": "172.18.0.5", "dst": "140.82.121.4"},
                {"src": "1.1.1.1", "dst": "8.8.8.8"}]
    store.annotate_names(log_rows)
    assert log_rows[0]["dst_name"] == "github.com"
    assert log_rows[0]["src_name"] is None
    assert log_rows[1]["dst_name"] is None
    assert store.dns_mappings(q="github") and store.dns_mappings(q="140.82")
    assert not store.dns_mappings(q="nope")
    assert store.clear_dns() == 3  # 1 mapping + 2 event rows
    assert store.dns_mappings() == [] and store.recent_dns_events() == []


def test_dns_tables_capped(store: Store):
    from dockfence.store import DNS_EVENTS_MAX, DNS_NAMES_MAX
    for i in range(DNS_NAMES_MAX + 20):
        store.upsert_dns(f"n{i}.example", f"10.{i // 256 % 250}.{i % 256}.1", ts=i)
    counts = store.dns_counts()
    assert counts["names"] == DNS_NAMES_MAX
    assert counts["events"] == DNS_EVENTS_MAX


def test_dns_events_age_pruned(store: Store):
    now = int(time.time())
    store.upsert_dns("a.example", "1.2.3.4", ts=now)
    store.upsert_dns("old.example", "1.2.3.5", ts=now - 30 * 86400)
    store.prune_retention(days=30, max_rows=0, event_days=7)
    assert store.dns_counts()["events"] == 1


def test_dns_rule_roundtrip_and_identity(store: Store):
    pid = store.get_or_create_policy("web")
    rid = store.add_rule(pid, {"direction": "out", "proto": "tcp", "port": 443,
                               "action": "accept", "dns": "example.com"})
    assert store.get_rule(rid).dns == "example.com"
    # identity tuple includes dns: same name+ports+action duplicates, others don't
    assert store.find_duplicate(pid, {"direction": "out", "proto": "tcp", "port": 443,
                                      "port_end": None, "cidr": "", "dns": "example.com",
                                      "action": "accept"})
    assert not store.find_duplicate(pid, {"direction": "out", "proto": "tcp", "port": 443,
                                          "port_end": None, "cidr": "", "dns": "other.com",
                                          "action": "accept"})


def test_dns_ip_tracking(store: Store):
    pid = store.get_or_create_policy("web")
    store.add_rule(pid, {"direction": "out", "proto": "tcp", "port": 443,
                         "action": "accept", "dns": "Example.COM"})
    assert store.dns_rule_names() == {"example.com"}
    assert store.upsert_dns("example.com", "203.0.113.4", ts=1000) is True
    assert store.upsert_dns("example.com", "203.0.113.4", ts=1010) is False  # refresh only
    assert store.upsert_dns("example.com", "198.51.100.8", ts=1010) is True
    assert store.upsert_dns("Example.COM", "2001:db8::1", ts=1010) is True  # NOCASE name match
    ips = store.dns_ips(["example.com"])
    assert sorted(ips["example.com"]["4"]) == ["198.51.100.8", "203.0.113.4"]
    assert ips["example.com"]["6"] == ["2001:db8::1"]
