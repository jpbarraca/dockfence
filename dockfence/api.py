"""REST API + WebUI. Flask, server-rendered templates + vanilla JS.
Auth: bearer token or cookie; no unauthenticated write paths."""

from __future__ import annotations

import json
import queue
import time

from flask import Flask, Response, abort, g, jsonify, redirect, render_template, request

from . import conntrack
from . import presets
from .models import ValidationError, validate_rule


def _client_ip(req) -> str:
    return req.headers.get("X-Forwarded-For", req.remote_addr or "-")


def _duplicate_msg(dup) -> str:
    label = f"rule #{dup.id}"
    if dup.comment:
        label += f" ({dup.comment})"
    return f"duplicate rule: an identical rule already exists ({label})"


def create_app(cfg, store, controller, watcher, nflog_consumer, bus, retention) -> Flask:
    app = Flask(__name__, template_folder="web/templates", static_folder="web/static")
    # localhost UI: never serve stale JS/CSS from the browser cache
    app.config["SEND_FILE_MAX_AGE_DEFAULT"] = 0
    app.config["SECRET"] = cfg.token

    # ---------------------------------------------------------------- auth --
    def authorized() -> bool:
        hdr = request.headers.get("Authorization", "")
        if hdr.startswith("Bearer ") and hdr[7:] == cfg.token:
            return True
        if request.cookies.get("fw_token") == cfg.token:
            return True
        if request.args.get("token") == cfg.token:
            return True
        return False

    @app.before_request
    def check_auth():
        if request.path == "/login" or request.path.startswith("/static/"):
            return
        if not authorized():
            if request.path.startswith("/api/"):
                abort(401)
            return redirect("/login")
        g.authorized = True

    def require_auth_or_401():
        if not authorized():
            abort(401)

    # ---------------------------------------------------------------- pages --
    @app.route("/login", methods=["GET", "POST"])
    def login():
        error = ""
        if request.method == "POST":
            if request.form.get("token") == cfg.token:
                resp = redirect("/")
                resp.set_cookie("fw_token", cfg.token, httponly=True, samesite="Lax")
                return resp
            error = "Invalid token"
        return render_template("login.html", error=error)

    @app.context_processor
    def _tpl_globals():
        # header toggles render their state server-side (no JS flash)
        return {
            "fw_logging": store.get_bool_setting("logging", False),
            "fw_dns_log": store.get_bool_setting("dns_log", False),
        }

    @app.route("/")
    def page_containers():
        return render_template("containers.html", mode=cfg.mode, ipv6=cfg.ipv6)

    @app.route("/dns")
    def page_dns():
        return render_template("dns.html", mode=cfg.mode, ipv6=cfg.ipv6)

    @app.route("/containers/<cid>")
    def page_container(cid: str):
        c = store.get_container(cid)
        if not c:
            abort(404)
        policy = store.policy_name(c.get("policy_id"))
        return render_template(
            "container_detail.html", c=c, policy=policy, mode=cfg.mode,
            logging=store.get_bool_setting("logging", False),
        )

    @app.route("/health")
    def page_health():
        return render_template(
            "health.html", cfg=cfg, health=_health(), events=store.recent_events(limit=50)
        )

    @app.template_filter("strftime")
    def strftime_filter(ts):
        return time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(int(ts)))

    # ------------------------------------------------------------- API: read --
    @app.route("/api/containers")
    def api_containers():
        counts = store.blocked_counts(24)
        by_dir = store.blocked_counts_by_dir(24)
        rows = []
        live = {c["id"]: c for c in watcher.snapshot()}
        for c in live.values():
            policy = c.get("policy") or c["name"]
            rules = []
            if c.get("opt_in"):
                pol = next((p for p in store.list_policies() if p["name"] == policy), None)
                if pol:
                    rules = store.list_rules(policy_id=pol["id"])
            rows.append({
                "id": c["id"],
                "short_id": c["id"][:12],
                "name": c["name"],
                "image": c.get("image", ""),
                "state": c.get("state"),
                "opt_in": c.get("opt_in", False),
                "policy": policy if c.get("opt_in") else None,
                "fw": _fw_status(c),
                "unfilterable_reason": watcher.unfilterable_reason(c) if c.get("opt_in") else None,
                "self": c.get("self", False),
                "networks": c.get("networks", []),
                "ips": c.get("ips", []),
                "ports": c.get("ports", []),
                "rules_total": sum(1 for r in rules if r.enabled),
                "blocked_24h": counts.get(c["id"], 0),
                "blocked_in": by_dir.get((c["id"], "in"), 0),
                "blocked_out": by_dir.get((c["id"], "out"), 0),
            })
        return jsonify(rows)

    def _fw_status(c: dict) -> str:
        if not c.get("opt_in"):
            return "untagged"
        if c.get("self"):
            return "self"
        if c.get("host_network"):
            return "unfilterable"
        if c.get("state") != "running":
            return "inactive"
        if cfg.mode == "disabled":
            return "disabled"
        ok = controller.status.get("last_apply_ok")
        if ok is False:
            return "error"
        return "monitor" if cfg.mode == "monitor" else "active"

    @app.route("/api/containers/<cid>/rules")
    def api_container_rules(cid: str):
        c = store.get_container(cid)
        if not c:
            abort(404)
        if not c.get("policy_id"):
            return jsonify([])
        rules = store.list_rules(policy_id=c["policy_id"])
        # dns rules: include the answer IPs currently observed for the name
        # (the contents of the rule's kernel set) so the UI can show coverage
        dns_names = sorted({r.dns for r in rules if r.dns})
        dns_ips = store.dns_ips(dns_names) if dns_names else {}
        out = []
        for r in rules:
            j = r.to_json()
            if r.dns:
                j["dns_ips"] = dns_ips.get(r.dns, {"4": [], "6": []})
            out.append(j)
        return jsonify(out)

    @app.route("/api/containers/<cid>/logs")
    def api_container_logs(cid: str):
        c = store.get_container(cid)
        if not c:
            abort(404)
        q = request.args
        rows = store.query_logs(
            container_id=c["id"],
            direction=q.get("direction"),
            proto=q.get("proto"),
            port=int(q["port"]) if q.get("port", "").isdigit() else None,
            since=int(q["since"]) if q.get("since", "").isdigit() else None,
            limit=int(q.get("limit", 200)),
            offset=int(q.get("offset", 0)),
        )
        return jsonify(store.annotate_names(rows))

    @app.route("/api/containers/<cid>/sessions")
    def api_container_sessions(cid: str):
        """Active traffic sessions for a container from the host conntrack."""
        c = watcher.get(cid)
        if c is None:
            abort(404)
        try:
            entries, source = conntrack.read_entries()
        except (OSError, RuntimeError) as exc:
            return jsonify({"available": False, "error": str(exc), "sessions": []})
        rows = conntrack.sessions_for(entries, set(c.get("ips") or []))
        return jsonify({"available": True, "source": source,
                        "sessions": store.annotate_names(rows)})

    @app.route("/api/containers/<cid>/flush", methods=["POST"])
    def api_container_flush(cid: str):
        """Flush helper: delete host conntrack entries touching the
        container's IPs so pending rule changes re-evaluate established
        flows immediately (established traffic bypasses the ruleset)."""
        c = watcher.get(cid)
        if c is None:
            abort(404)
        ips = [ip for ip in (c.get("ips") or []) if ip]
        if not ips:
            return jsonify({"available": True, "deleted": 0, "ips": [], "errors": []})
        try:
            res = conntrack.flush_for_ips(set(ips))
        except (OSError, RuntimeError) as exc:
            return jsonify({"available": False, "error": str(exc),
                            "deleted": 0, "ips": ips, "errors": []})
        return jsonify({"available": True, "deleted": res["deleted"],
                        "ips": ips, "errors": res["errors"]})

    @app.route("/api/containers/<cid>/counters")
    def api_container_counters(cid: str):
        """Live per-rule packet/byte counters. nftables counters are in-kernel
        memory increments read on demand — no logging/syslog involvement."""
        c = store.get_container(cid)
        if not c:
            abort(404)
        applier = getattr(controller, "applier", None)
        all_counters = applier.rule_counters() if applier is not None else {}
        rule_ids = {r.id for r in store.list_rules(policy_id=c.get("policy_id"))
                    if r.id is not None} if c.get("policy_id") else set()
        rows = [{"rule_id": rid, **all_counters[rid]}
                for rid in sorted(all_counters) if rid in rule_ids]
        return jsonify({"available": applier is not None, "counters": rows})

    @app.route("/api/edges")
    def api_edges():
        """Live connection edges for the topology diagram, aggregated from the
        host conntrack: container ↔ container (cross-network) and container ↔
        outside. Same-bridge traffic is L2-switched and not conntrack-tracked.
        Read-only — no logging involved."""
        try:
            entries, _source = conntrack.read_entries()
        except (OSError, RuntimeError) as exc:
            return jsonify({"available": False, "error": str(exc),
                            "internal": [], "external": []})
        ip_map: dict[str, str] = {}
        ip_net: dict[str, str] = {}
        for c in watcher.snapshot():
            for ip in c.get("ips") or []:
                ip_map[ip] = c["id"]
            for net in c.get("networks") or []:
                for ip in (net.get("v4"), net.get("v6")):
                    if ip:
                        ip_net[ip] = net["name"]
        internal: dict[tuple, dict] = {}
        external: dict[tuple, dict] = {}
        for e in conntrack.sessions_for(entries, set(ip_map), limit=5000):
            s, d = ip_map.get(e["src"]), ip_map.get(e["dst"])
            if s and d and s != d:
                key, row = (s, d, e["proto"]), internal
                # which network carried the flow: the delivery side wins
                net = ip_net.get(e["dst"]) or ip_net.get(e["src"])
            elif s or d:
                cid, direction = (s, "out") if s else (d, "in")
                key, row = (cid, direction, e["proto"]), external
                local = e["src"] if s else (e["dst"] or e.get("reply_src") or "")
                net = ip_net.get(local)
            else:
                # published-port DNAT: the container is only the reply source
                cid = ip_map.get(e.get("reply_src") or "")
                if not cid:
                    continue
                key, row = (cid, "in", e["proto"]), external
                net = ip_net.get(e.get("reply_src") or "")
            a = row.setdefault(key, {"count": 0, "established": 0, "net": None})
            if net and not a["net"]:
                a["net"] = net
            a["count"] += 1
            a["established"] += 1 if e["state"] == "ESTABLISHED" else 0
        return jsonify({
            "available": True,
            "internal": [{"src": s, "dst": d, "proto": p, **v}
                         for (s, d, p), v in sorted(internal.items())],
            "external": [{"cid": cid, "dir": dr, "proto": p, **v}
                         for (cid, dr, p), v in sorted(external.items())],
        })

    @app.route("/api/settings")
    def api_settings_get():
        return jsonify({
            "logging": store.get_bool_setting("logging", False),
            "dns_log": store.get_bool_setting("dns_log", False),
        })

    @app.route("/api/settings", methods=["PATCH"])
    def api_settings_patch():
        payload = request.get_json(silent=True) or {}
        kv: dict[str, bool] = {}
        for key in ("logging", "dns_log"):
            if key in payload:
                if not isinstance(payload[key], bool):
                    return jsonify({"error": f"{key} must be a boolean"}), 400
                kv[key] = payload[key]
        if not kv:
            return jsonify({"error": "nothing to update (allowed: logging, dns_log)"}), 400
        store.set_settings(kv)
        # both toggles change the rendered kernel table (nflog rules on/off,
        # dns capture chains in/out) — re-render + atomic apply
        controller.rules_changed()
        return jsonify({
            "logging": store.get_bool_setting("logging", False),
            "dns_log": store.get_bool_setting("dns_log", False),
        })

    @app.route("/api/dns")
    def api_dns():
        q = (request.args.get("q") or "").strip()
        limit = int(request.args["limit"]) if request.args.get("limit", "").isdigit() else 1000
        return jsonify(store.dns_mappings(q=q, limit=limit))

    @app.route("/api/dns/recent")
    def api_dns_recent():
        limit = int(request.args["limit"]) if request.args.get("limit", "").isdigit() else 100
        return jsonify(store.recent_dns_events(limit=limit))

    @app.route("/api/dns", methods=["DELETE"])
    def api_dns_clear():
        return jsonify({"cleared": store.clear_dns()})

    @app.route("/api/logs/stream")
    def api_logs_stream():
        require_auth_or_401()
        container_id = request.args.get("container", "") or None
        max_events = int(request.args.get("max_events", "0") or "0")  # test/automation cap
        q = bus.subscribe()
        sent = 0

        def gen():
            nonlocal sent
            try:
                yield "retry: 3000\n\n"
                while True:
                    try:
                        row = q.get(timeout=15)
                        if container_id and row.get("container_id") != container_id \
                           and not row.get("container_id", "").startswith(container_id):
                            continue
                        yield f"data: {json.dumps(row)}\n\n"
                        sent += 1
                        if max_events and sent >= max_events:
                            return
                    except queue.Empty:
                        yield ": keepalive\n\n"
            finally:
                bus.unsubscribe(q)

        return Response(gen(), mimetype="text/event-stream")

    # ------------------------------------------------------------ API: write --
    @app.route("/api/containers/<cid>/rules", methods=["POST"])
    def api_add_rule(cid: str):
        c = store.get_container(cid)
        if not c:
            abort(404)
        if not c.get("policy_id"):
            return jsonify({"error": "container is not firewall-managed"}), 400
        payload = request.get_json(silent=True) or request.form.to_dict()
        try:
            fields = validate_rule(payload, partial=False)
        except ValidationError as exc:
            return jsonify({"error": str(exc)}), 400
        dup = store.find_duplicate(c["policy_id"], fields)
        if dup:
            return jsonify({"error": _duplicate_msg(dup)}), 409
        rule_id = store.add_rule(c["policy_id"], fields)
        controller.rules_changed()
        return jsonify(store.get_rule(rule_id).to_json()), 201

    @app.route("/api/rules/<int:rule_id>", methods=["PATCH"])
    def api_patch_rule(rule_id: int):
        rule = store.get_rule(rule_id)
        if not rule:
            abort(404)
        payload = request.get_json(silent=True) or request.form.to_dict()
        # validate the MERGED rule, so a partial patch cannot create an
        # invalid combination (e.g. proto=icmp patched onto a tcp:53 rule)
        merged = rule.to_json()
        merged.update(payload)
        for k in ("id", "policy_id", "created"):
            merged.pop(k, None)
        try:
            fields = validate_rule(merged, partial=False)
        except ValidationError as exc:
            return jsonify({"error": str(exc)}), 400
        dup = store.find_duplicate(rule.policy_id, fields, exclude_id=rule_id)
        if dup:
            return jsonify({"error": _duplicate_msg(dup)}), 409
        store.update_rule(rule_id, fields)
        controller.rules_changed()
        return jsonify(store.get_rule(rule_id).to_json())

    @app.route("/api/rules/<int:rule_id>", methods=["DELETE"])
    def api_delete_rule(rule_id: int):
        if not store.delete_rule(rule_id):
            abort(404)
        controller.rules_changed()
        return jsonify({"deleted": rule_id})

    @app.route("/api/presets")
    def api_presets():
        require_auth_or_401()
        return jsonify(presets.catalog_json())

    @app.route("/api/containers/<cid>/presets/<name>", methods=["POST", "DELETE"])
    def api_preset(cid: str, name: str):
        require_auth_or_401()
        c = store.get_container(cid)
        if not c:
            abort(404)
        if not c.get("policy_id"):
            return jsonify({"error": "container is not firewall-managed"}), 400
        if name not in presets.CATALOG:
            return jsonify({"error": f"unknown preset '{name}'"}), 400
        if request.method == "POST":
            try:
                result = presets.apply_preset(store, c["policy_id"], name)
            except ValidationError as exc:
                return jsonify({"error": str(exc)}), 400
            controller.rules_changed()
            return jsonify(result), 201
        removed = presets.delete_preset(store, c["policy_id"], name)
        controller.rules_changed()
        return jsonify({"preset": name, "removed": removed})

    @app.route("/api/resync", methods=["POST"])
    def api_resync():
        ok = controller.resync(reason="manual")
        return jsonify({"ok": ok, "status": controller.status}), (200 if ok else 500)

    # ------------------------------------------------------- health / metrics --
    def _health() -> dict:
        return {
            "mode": cfg.mode,
            "ipv6": cfg.ipv6,
            "tls": bool(cfg.tls),
            "controller": controller.status,
            "docker": watcher.ping(),
            "nflog": {
                "bound": nflog_consumer.status.bound,
                "group": cfg.log_group,
                "received": nflog_consumer.status.received,
                "stored": nflog_consumer.status.stored,
                "dropped": nflog_consumer.status.dropped,
                "error": nflog_consumer.status.error,
            },
            "retention": {
                "days": cfg.retention_days,
                "max_rows": cfg.retention_max_rows,
                "event_days": cfg.event_retention_days,
                "last_sweep": retention.last_stats,
            },
            "logging": {
                # packet logs + dns answer capture are UI toggles, off by default
                "enabled": store.get_bool_setting("logging", False),
                "dns": store.get_bool_setting("dns_log", False),
                "dns_group": cfg.dns_group,
                "dns_names": store.dns_counts()["names"],
            },
            "db": {"path": store.path, "integrity": "ok" if store.integrity_ok() else "CORRUPT"},
            "time": time.time(),
        }

    @app.route("/api/health")
    def api_health():
        return jsonify(_health())

    @app.route("/api/metrics")
    def api_metrics():
        require_auth_or_401()
        h = _health()
        by_dir = store.blocked_counts_by_dir(24)
        lines = [
            "# HELP dfw_up controller up",
            "# TYPE dfw_up gauge",
            "dfw_up 1",
            "# HELP dfw_containers_tagged containers behind the firewall",
            "# TYPE dfw_containers_tagged gauge",
            f'dfw_containers_tagged {h["controller"].get("tagged", 0)}',
            "# HELP dfw_rules_enabled enabled rules",
            "# TYPE dfw_rules_enabled gauge",
            f"dfw_rules_enabled {sum(1 for r in store.list_rules() if r.enabled)}",
            "# HELP dfw_last_apply_success_timestamp last good apply",
            "# TYPE dfw_last_apply_success_timestamp gauge",
            f'dfw_last_apply_success_timestamp {h["controller"].get("last_apply_ts") or 0}',
            "# HELP dfw_apply_failures_total failed applies",
            "# TYPE dfw_apply_failures_total counter",
            f'dfw_apply_failures_total {h["controller"].get("apply_failures", 0)}',
            "# HELP dfw_nflog_dropped_total nflog lines dropped by kernel queue",
            "# TYPE dfw_nflog_dropped_total counter",
            f'dfw_nflog_dropped_total {h["nflog"].get("dropped", 0)}',
            "# HELP dfw_blocked_24h blocked attempts per container and direction (24h)",
            "# TYPE dfw_blocked_24h gauge",
        ]
        for (cid, dirn), n in sorted(by_dir.items()):
            name = (store.get_container(cid) or {}).get("name", cid[:12])
            lines.append(
                f'dfw_blocked_24h{{container="{name}",id="{cid[:12]}",direction="{dirn}"}} {n}'
            )
        return Response("\n".join(lines) + "\n", mimetype="text/plain")

    # -------------------------------------------------------- export / import --
    @app.route("/api/export")
    def api_export():
        return jsonify(store.export_json())

    @app.route("/api/import", methods=["POST"])
    def api_import():
        data = request.get_json(silent=True)
        if not isinstance(data, dict) or "policies" not in data:
            return jsonify({"error": "expected {version, policies: [...]}"}), 400
        try:
            n = store.import_json(data)
        except ValidationError as exc:
            return jsonify({"error": str(exc)}), 400
        controller.rules_changed()
        return jsonify({"imported_rules": n})

    @app.route("/api/events")
    def api_events():
        return jsonify(store.recent_events(limit=int(request.args.get("limit", 100))))

    @app.errorhandler(404)
    def not_found(_e):
        if request.path.startswith("/api/"):
            return jsonify({"error": "not found"}), 404
        return render_template("error.html", code=404), 404

    @app.errorhandler(401)
    def unauthorized(_e):
        if request.path.startswith("/api/"):
            return jsonify({"error": "unauthorized"}), 401
        return redirect("/login")

    return app
