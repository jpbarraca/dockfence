"""API tests via Flask test client (fakes replace docker/nft backends)."""

import time

import pytest

from dockfence import conntrack
from dockfence.api import create_app
from dockfence.nflog import EventBus, NFLogStatus


class FakeWatcher:
    def __init__(self, containers):
        self._c = containers

    def snapshot(self):
        return list(self._c.values())

    def get(self, cid):
        for c in self._c.values():
            if c["id"].startswith(cid):
                return c
        return None

    def unfilterable_reason(self, c):
        if c.get("self"):
            return "firewall container itself (never tagged)"
        if c.get("host_network"):
            return "host network: no veth to filter"
        if c.get("state") != "running":
            return f"not running ({c.get('state')})"
        return None

    def ping(self):
        return {"status": "ok", "version": "27.0"}


class FakeController:
    def __init__(self):
        self.status = {"last_apply_ts": time.time(), "last_apply_ok": True,
                       "last_error": None, "applies": 1, "apply_failures": 0, "tagged": 1}
        self.applied = 0

    def rules_changed(self):
        self.applied += 1
        return True

    def resync(self, reason="resync"):
        self.applied += 1
        return True


class FakeNflog:
    def __init__(self):
        self.status = NFLogStatus(bound=True, received=3, stored=2, dropped=0)


class FakeRetention:
    last_stats = None


@pytest.fixture
def env(cfg, store):
    web = {
        "id": "abcdef123456fedcba98", "name": "web", "state": "running",
        "opt_in": True, "policy": "web", "ips": ["172.18.0.5"],
        "networks": [{"name": "bridge", "v4": "172.18.0.5", "v6": "",
                      "gateway4": "172.18.0.1", "gateway6": ""}],
        "ports": [{"container": "80/tcp", "host": "0.0.0.0:8080"}],
        "host_network": False, "self": False, "image": "nginx",
    }
    plain = {
        "id": "999999999999deadbeef00", "name": "curl", "state": "running",
        "opt_in": False, "policy": None, "ips": ["172.18.0.7"], "networks": [],
        "ports": [], "host_network": False, "self": False, "image": "curl",
    }
    watcher = FakeWatcher({web["id"]: web, plain["id"]: plain})
    controller = FakeController()
    bus = EventBus()
    app = create_app(cfg, store, controller, watcher, FakeNflog(), bus, FakeRetention())
    app.config["TESTING"] = True
    # simulate a controller resync: containers in the store
    store.upsert_container({"id": web["id"], "name": "web", "ips": web["ips"],
                            "networks": web["networks"], "state": "running"})
    store.upsert_container({"id": plain["id"], "name": "curl", "ips": plain["ips"],
                            "networks": [], "state": "running"})
    pid = store.get_or_create_policy("web")
    store.upsert_container({"id": web["id"], "name": "web", "policy_id": pid,
                            "ips": web["ips"], "networks": web["networks"], "state": "running"})
    store.add_rule(pid, {"direction": "out", "proto": "tcp", "port": 443, "action": "accept"})
    return {"app": app.test_client(), "store": store, "controller": controller,
            "web": web, "plain": plain, "bus": bus}


AUTH = {"Authorization": "Bearer test-token"}


def test_requires_auth(env):
    r = env["app"].get("/api/containers")
    assert r.status_code == 401
    r = env["app"].get("/api/containers", headers=AUTH)
    assert r.status_code == 200


def test_containers_shape(env):
    r = env["app"].get("/api/containers", headers=AUTH).get_json()
    by_name = {c["name"]: c for c in r}
    assert by_name["web"]["fw"] == "active"
    assert by_name["web"]["blocked_24h"] == 0
    assert by_name["web"]["policy"] == "web"
    assert by_name["curl"]["fw"] == "untagged"


def test_rule_crud_and_apply(env):
    cid = env["web"]["id"]
    r = env["app"].post(f"/api/containers/{cid}/rules", headers=AUTH, json={
        "direction": "in", "proto": "tcp", "port": 8080, "cidr": "10.0.0.0/8",
        "action": "accept", "comment": "web"})
    assert r.status_code == 201, r.get_json()
    rid = r.get_json()["id"]
    assert env["controller"].applied == 1

    r = env["app"].patch(f"/api/rules/{rid}", headers=AUTH, json={"enabled": False})
    assert r.get_json()["enabled"] is False
    assert env["store"].get_rule(rid).enabled is False

    r = env["app"].delete(f"/api/rules/{rid}", headers=AUTH)
    assert r.status_code == 200
    assert env["store"].get_rule(rid) is None


def test_duplicate_rule_rejected(env):
    cid = env["web"]["id"]
    body = {"direction": "out", "proto": "tcp", "port": 443, "action": "accept"}
    # the env fixture already created exactly this tuple
    r = env["app"].post(f"/api/containers/{cid}/rules", headers=AUTH, json=body)
    assert r.status_code == 409
    assert "duplicate" in r.get_json()["error"]
    # comment is not part of the identity → still a duplicate
    r = env["app"].post(f"/api/containers/{cid}/rules", headers=AUTH,
                        json={**body, "comment": "different comment"})
    assert r.status_code == 409
    # a different cidr makes it a different rule
    r = env["app"].post(f"/api/containers/{cid}/rules", headers=AUTH,
                        json={**body, "cidr": "203.0.113.4/32"})
    assert r.status_code == 201
    # cidr normalization: host address == the /32 of the same network
    r = env["app"].post(f"/api/containers/{cid}/rules", headers=AUTH,
                        json={**body, "cidr": "203.0.113.4"})
    assert r.status_code == 409


def test_patch_rule_rejects_duplicate(env):
    cid = env["web"]["id"]
    r = env["app"].post(f"/api/containers/{cid}/rules", headers=AUTH,
                        json={"direction": "out", "proto": "udp", "port": 53, "action": "accept"})
    rid = r.get_json()["id"]
    # patching it onto the env fixture's out tcp 443 accept tuple → duplicate
    r = env["app"].patch(f"/api/rules/{rid}", headers=AUTH, json={"proto": "tcp", "port": 443})
    assert r.status_code == 409
    assert "duplicate" in r.get_json()["error"]
    # a patch that keeps the rule's own identity is fine
    r = env["app"].patch(f"/api/rules/{rid}", headers=AUTH, json={"comment": "identity kept"})
    assert r.status_code == 200


class FakeApplier:
    def __init__(self, counters):
        self._c = counters

    def rule_counters(self):
        return self._c


def test_container_counters_endpoint(env):
    rules = env["app"].get(f"/api/containers/{env['web']['id']}/rules",
                           headers=AUTH).get_json()
    rid = rules[0]["id"]
    env["controller"].applier = FakeApplier({rid: {"packets": 12, "bytes": 3456},
                                            999: {"packets": 5, "bytes": 300}})
    r = env["app"].get(f"/api/containers/{env['web']['id']}/counters", headers=AUTH)
    assert r.status_code == 200
    data = r.get_json()
    assert data["available"] is True
    # only rules of THIS container's policy are reported
    assert data["counters"] == [{"rule_id": rid, "packets": 12, "bytes": 3456}]


def test_container_counters_unavailable(env):
    # FakeController has no applier → endpoint reports unavailable, not a crash
    r = env["app"].get(f"/api/containers/{env['web']['id']}/counters", headers=AUTH)
    assert r.status_code == 200
    assert r.get_json() == {"available": False, "counters": []}


def test_rule_validation_400(env):
    cid = env["web"]["id"]
    r = env["app"].post(f"/api/containers/{cid}/rules", headers=AUTH,
                        json={"direction": "sideways"})
    assert r.status_code == 400
    r = env["app"].post(f"/api/containers/{cid}/rules", headers=AUTH,
                        json={"proto": "tcp"})  # missing port
    assert r.status_code == 400


def test_untagged_container_rejects_rules(env):
    r = env["app"].post(f"/api/containers/{env['plain']['id']}/rules",
                        headers=AUTH, json={"direction": "out"})
    assert r.status_code == 400


def test_logs_query_and_stream(env):
    store = env["store"]
    store.insert_log({"ts": int(time.time()), "container_id": env["web"]["id"],
                      "dir": "out", "src": "172.18.0.5", "dst": "1.2.3.4",
                      "proto": "tcp", "sport": 1, "dport": 443, "family": 4})
    r = env["app"].get(f"/api/containers/{env['web']['id']}/logs", headers=AUTH)
    assert r.status_code == 200
    rows = r.get_json()
    assert len(rows) == 1 and rows[0]["dport"] == 443
    # SSE: pre-fill a queue so the route (which subscribes on read) sees one
    # live row; the stream terminates at the max_events cap.
    import queue as qmod

    pre = qmod.Queue()
    pre.put({"container_id": env["web"]["id"], "dir": "out", "src": "172.18.0.5",
             "dst": "1.2.3.4", "proto": "tcp", "sport": 5, "dport": 443})
    env["bus"].subscribe = lambda: pre
    r = env["app"].get("/api/logs/stream?max_events=1", headers=AUTH)
    assert r.status_code == 200
    assert r.content_type.startswith("text/event-stream")
    assert b'"dport": 443' in r.data or b'"dport":443' in r.data


def test_health_and_metrics(env):
    r = env["app"].get("/api/health", headers=AUTH)
    assert r.status_code == 200
    assert r.get_json()["nflog"]["bound"] is True
    r = env["app"].get("/api/metrics", headers=AUTH)
    assert b"dfw_up 1" in r.data


def test_export_import(env):
    r = env["app"].get("/api/export", headers=AUTH)
    data = r.get_json()
    assert data["policies"][0]["name"] == "web"
    r = env["app"].post("/api/import", headers=AUTH, json=data)
    assert r.status_code == 200


def test_unauthorized_writes_blocked(env):
    r = env["app"].post("/api/resync")
    assert r.status_code == 401
    r = env["app"].delete("/api/rules/1")
    assert r.status_code == 401


def test_presets_catalog_endpoint(env):
    r = env["app"].get("/api/presets")
    assert r.status_code == 401
    r = env["app"].get("/api/presets", headers=AUTH)
    assert r.status_code == 200
    names = {p["name"] for p in r.get_json()}
    assert {"harden-egress", "deny-private-out", "dns-out", "web-out"} <= names


def test_preset_apply_delete_and_guards(env):
    c = env["app"]
    before = env["controller"].applied
    r = c.post("/api/containers/web/presets/dns-out", headers=AUTH)
    assert r.status_code == 201
    body = r.get_json()
    assert len(body["added"]) == 2 and body["skipped"] == 0
    assert env["controller"].applied == before + 1  # rules re-applied
    # idempotent second apply
    r = c.post("/api/containers/web/presets/dns-out", headers=AUTH)
    assert r.status_code == 201 and r.get_json()["added"] == []
    # unknown preset
    r = c.post("/api/containers/web/presets/nope", headers=AUTH)
    assert r.status_code == 400
    # unmanaged container
    r = c.post(f"/api/containers/{env['plain']['id']}/presets/dns-out", headers=AUTH)
    assert r.status_code == 400
    # removal
    r = c.delete("/api/containers/web/presets/dns-out", headers=AUTH)
    assert r.status_code == 200 and r.get_json()["removed"] == 2


def test_containers_blocked_by_direction(env):
    r = env["app"].get("/api/containers", headers=AUTH)
    row = next(x for x in r.get_json() if x["name"] == "web")
    assert "blocked_in" in row and "blocked_out" in row


def test_patch_validates_merged_rule(env):
    # fixture rule 1 is out/tcp/443 — patching proto=icmp would create an
    # invalid merged rule (icmp must not carry a port) and must be rejected
    r = env["app"].patch("/api/rules/1", headers=AUTH, json={"proto": "icmp"})
    assert r.status_code == 400
    # position patches are honored (needed to reorder around deny presets)
    r = env["app"].patch("/api/rules/1", headers=AUTH, json={"position": 0})
    assert r.status_code == 200
    assert env["store"].get_rule(1).position == 0
    r = env["app"].patch("/api/rules/1", headers=AUTH, json={"port": 8443})
    assert r.status_code == 200
    assert env["store"].get_rule(1).port == 8443


def test_metrics_blocked_has_direction_label(env):
    env["store"].insert_log({
        "ts": int(time.time()), "container_id": env["web"]["id"],
        "policy_id": 1, "dir": "out", "family": 4,
        "src": "172.18.0.5", "dst": "10.0.0.1", "proto": "tcp", "dport": 445,
    })
    r = env["app"].get("/api/metrics", headers=AUTH)
    assert 'dfw_blocked_24h{container="web",id="abcdef123456",direction="out"} 1' in r.get_data(as_text=True)


def test_pages_render(env):
    r = env["app"].get("/", headers=AUTH)
    assert r.status_code == 200
    r = env["app"].get(f"/containers/{env['web']['id']}", headers=AUTH)
    assert r.status_code == 200
    assert b"web" in r.data


def test_settings_default_off_and_patch(env):
    r = env["app"].get("/api/settings", headers=AUTH)
    assert r.get_json() == {"logging": False, "dns_log": False}
    r = env["app"].patch("/api/settings", headers=AUTH, json={"logging": True})
    assert r.get_json()["logging"] is True
    assert env["controller"].applied == 1  # kernel re-render triggered
    assert env["store"].get_bool_setting("logging") is True  # persisted
    r = env["app"].patch("/api/settings", headers=AUTH, json={"logging": "yes"})
    assert r.status_code == 400
    r = env["app"].patch("/api/settings", headers=AUTH, json={})
    assert r.status_code == 400
    # dns toggle also re-renders
    before = env["controller"].applied
    env["app"].patch("/api/settings", headers=AUTH, json={"dns_log": True})
    assert env["controller"].applied == before + 1


def test_dns_endpoints_and_log_annotation(env):
    store = env["store"]
    store.upsert_dns("api.github.com", "140.82.121.6", "192.168.1.1")
    r = env["app"].get("/api/dns", headers=AUTH)
    assert r.get_json()[0]["name"] == "api.github.com"
    r = env["app"].get("/api/dns?q=140.82", headers=AUTH)
    assert len(r.get_json()) == 1
    r = env["app"].get("/api/dns/recent", headers=AUTH)
    assert r.get_json()[0]["ip"] == "140.82.121.6"
    # blocked-connection rows are annotated with the learned hostname
    store.insert_log({"ts": int(time.time()), "container_id": env["web"]["id"],
                      "dir": "out", "src": "172.18.0.5", "dst": "140.82.121.6",
                      "proto": "tcp", "sport": 44444, "dport": 443})
    rows = env["app"].get(f"/api/containers/{env['web']['id']}/logs",
                          headers=AUTH).get_json()
    assert rows[0]["dst_name"] == "api.github.com"
    r = env["app"].delete("/api/dns", headers=AUTH)
    assert r.get_json()["cleared"] >= 1
    assert env["app"].get("/api/dns", headers=AUTH).get_json() == []


def test_health_reports_logging(env):
    h = env["app"].get("/api/health", headers=AUTH).get_json()
    assert h["logging"]["enabled"] is False
    assert h["logging"]["dns_group"] == 6
    assert "dns_names" in h["logging"]


def test_container_sessions_endpoint(env, monkeypatch):
    entries = [{
        "family": "ipv4", "proto": "tcp", "state": "ESTABLISHED", "timeout": 43199,
        "assured": True, "src": "172.18.0.5", "sport": 41234,
        "dst": "140.82.121.4", "dport": 443,
        "reply_src": "140.82.121.4", "reply_sport": 443,
        "reply_dst": "172.18.0.1", "reply_dport": 41234,
    }]
    monkeypatch.setattr(conntrack, "read_entries", lambda *a, **k: (entries, "netlink"))
    r = env["app"].get(f"/api/containers/{env['web']['id']}/sessions", headers=AUTH)
    assert r.status_code == 200
    data = r.get_json()
    assert data["available"] is True and data["source"] == "netlink"
    s = data["sessions"][0]
    assert s["dir"] == "out" and s["dport"] == 443
    assert s["dst_name"] is None  # no dns mapping recorded in the store yet


def test_container_sessions_unavailable(env, monkeypatch):
    def boom(*a, **kw):
        raise FileNotFoundError("conntrack unavailable: no /proc/net/nf_conntrack")

    monkeypatch.setattr(conntrack, "read_entries", boom)
    r = env["app"].get(f"/api/containers/{env['web']['id']}/sessions", headers=AUTH)
    assert r.status_code == 200
    data = r.get_json()
    assert data["available"] is False and data["sessions"] == []
    assert "conntrack unavailable" in data["error"]


def test_container_sessions_unknown_container(env):
    assert env["app"].get("/api/containers/zzzz/sessions", headers=AUTH).status_code == 404


def _edge_entry(**kw):
    e = {"family": "ipv4", "proto": "tcp", "state": "ESTABLISHED", "timeout": 120,
         "assured": True, "sport": 41234, "dport": 443,
         "reply_src": "", "reply_sport": 0, "reply_dst": "", "reply_dport": 0}
    e.update(kw)
    return e


def test_edges_internal_and_external(env, monkeypatch):
    entries = [
        # web → curl (cross-container), and web → outside
        _edge_entry(src="172.18.0.5", dst="172.18.0.7", reply_src="172.18.0.7",
                    reply_dst="172.18.0.5"),
        _edge_entry(src="172.18.0.5", dst="140.82.121.4", reply_src="140.82.121.4",
                    reply_dst="172.18.0.5"),
    ]
    monkeypatch.setattr(conntrack, "read_entries", lambda *a, **k: (entries, "netlink"))
    data = env["app"].get("/api/edges", headers=AUTH).get_json()
    assert data["available"] is True
    # curl has no networks → the delivery net falls back to the source side ("bridge")
    assert data["internal"] == [{"src": env["web"]["id"], "dst": env["plain"]["id"],
                                 "proto": "tcp", "count": 1, "established": 1,
                                 "net": "bridge"}]
    assert data["external"] == [{"cid": env["web"]["id"], "dir": "out", "proto": "tcp",
                                 "count": 1, "established": 1, "net": "bridge"}]


def test_edges_dnat_inbound_via_reply_src(env, monkeypatch):
    # published-port flow: src/dst are the client and the HOST ip, the container
    # is only visible as the reply source — must classify as an external "in" edge
    entries = [_edge_entry(src="203.0.113.9", dst="198.51.100.20", dport=8080,
                           reply_src="172.18.0.5", reply_dst="203.0.113.9")]
    monkeypatch.setattr(conntrack, "read_entries", lambda *a, **k: (entries, "netlink"))
    data = env["app"].get("/api/edges", headers=AUTH).get_json()
    assert data["available"] is True
    assert data["internal"] == []
    assert data["external"] == [{"cid": env["web"]["id"], "dir": "in", "proto": "tcp",
                                 "count": 1, "established": 1, "net": "bridge"}]


def test_edges_unavailable(env, monkeypatch):
    def boom(*a, **kw):
        raise RuntimeError("conntrack tool failed")

    monkeypatch.setattr(conntrack, "read_entries", boom)
    data = env["app"].get("/api/edges", headers=AUTH).get_json()
    assert data["available"] is False
    assert data["internal"] == [] and data["external"] == []
    assert "conntrack tool failed" in data["error"]


def test_container_flush_endpoint(env, monkeypatch):
    seen = {}

    def fake_flush(ips, **kw):
        seen["ips"] = ips
        return {"deleted": 2, "errors": []}

    monkeypatch.setattr(conntrack, "flush_for_ips", fake_flush)
    r = env["app"].post(f"/api/containers/{env['web']['id']}/flush", headers=AUTH)
    assert r.status_code == 200
    data = r.get_json()
    assert data["available"] is True and data["deleted"] == 2
    assert data["errors"] == []
    assert seen["ips"] == {"172.18.0.5"}  # container IPs passed through


def test_container_flush_unavailable(env, monkeypatch):
    def boom(ips, **kw):
        raise FileNotFoundError("conntrack flush unavailable: no 'conntrack' binary installed")

    monkeypatch.setattr(conntrack, "flush_for_ips", boom)
    r = env["app"].post(f"/api/containers/{env['web']['id']}/flush", headers=AUTH)
    assert r.status_code == 200
    data = r.get_json()
    assert data["available"] is False and data["deleted"] == 0
    assert "conntrack flush unavailable" in data["error"]


def test_container_flush_unknown_container(env):
    r = env["app"].post("/api/containers/zzzz/flush", headers=AUTH)
    assert r.status_code == 404
