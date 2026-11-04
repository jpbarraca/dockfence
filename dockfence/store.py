"""SQLite store: the source of truth for policies, rules, container inventory,
blocked-connection logs and events."""

from __future__ import annotations

import sqlite3
import threading
import time
from typing import Any, Iterable

from .models import Rule, normalize_dns_name

SCHEMA = """
PRAGMA user_version = 1;

CREATE TABLE IF NOT EXISTS policies (
    id       INTEGER PRIMARY KEY,
    name     TEXT NOT NULL UNIQUE,
    created  TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS rules (
    id         INTEGER PRIMARY KEY,
    policy_id  INTEGER NOT NULL REFERENCES policies(id) ON DELETE CASCADE,
    direction  TEXT NOT NULL CHECK (direction IN ('in','out')),
    proto      TEXT NOT NULL CHECK (proto IN ('tcp','udp','icmp','any')),
    port       INTEGER,
    port_end   INTEGER,
    cidr       TEXT NOT NULL DEFAULT '',
    dns        TEXT NOT NULL DEFAULT '',
    action     TEXT NOT NULL CHECK (action IN ('accept','drop')),
    enabled    INTEGER NOT NULL DEFAULT 1,
    position   INTEGER NOT NULL DEFAULT 0,
    comment    TEXT NOT NULL DEFAULT '',
    log        INTEGER NOT NULL DEFAULT 0,
    created    TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_rules_policy ON rules(policy_id, position);

CREATE TABLE IF NOT EXISTS containers (
    id            TEXT PRIMARY KEY,
    name          TEXT NOT NULL,
    policy_id     INTEGER REFERENCES policies(id) ON DELETE SET NULL,
    ips           TEXT NOT NULL DEFAULT '[]',
    networks      TEXT NOT NULL DEFAULT '[]',
    state         TEXT NOT NULL DEFAULT '',
    host_network  INTEGER NOT NULL DEFAULT 0,
    self          INTEGER NOT NULL DEFAULT 0,
    first_seen    TEXT NOT NULL,
    last_seen     TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS logs (
    id           INTEGER PRIMARY KEY,
    ts           INTEGER NOT NULL,             -- epoch seconds
    container_id TEXT NOT NULL,
    policy_id    INTEGER,
    dir          TEXT NOT NULL DEFAULT '',
    family       INTEGER NOT NULL DEFAULT 4,   -- 4 | 6
    src          TEXT NOT NULL DEFAULT '',
    dst          TEXT NOT NULL DEFAULT '',
    proto        TEXT NOT NULL DEFAULT '',
    sport        INTEGER,
    dport        INTEGER,
    rule_id      INTEGER,
    ifaces       TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_logs_container ON logs(container_id, ts DESC);
CREATE INDEX IF NOT EXISTS idx_logs_ts ON logs(ts);

CREATE TABLE IF NOT EXISTS events (
    id   INTEGER PRIMARY KEY,
    ts   INTEGER NOT NULL,
    kind TEXT NOT NULL,
    msg  TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts DESC);

-- runtime toggles (UI): packet logging + DNS answer capture, both default off
CREATE TABLE IF NOT EXISTS settings (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

-- DNS answers captured from NFLOG: learned name <-> ip mapping so firewall
-- log destinations can be shown with their hostnames
CREATE TABLE IF NOT EXISTS dns_names (
    name       TEXT NOT NULL,
    ip         TEXT NOT NULL,
    resolver   TEXT NOT NULL DEFAULT '',
    first_seen INTEGER NOT NULL,
    last_seen  INTEGER NOT NULL,
    hits       INTEGER NOT NULL DEFAULT 1,
    PRIMARY KEY (name, ip)
);
CREATE INDEX IF NOT EXISTS idx_dns_names_ip ON dns_names(ip);

CREATE TABLE IF NOT EXISTS dns_events (
    id       INTEGER PRIMARY KEY,
    ts       INTEGER NOT NULL,
    resolver TEXT NOT NULL DEFAULT '',
    name     TEXT NOT NULL,
    ip       TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_dns_events_ts ON dns_events(ts DESC);
"""

now_iso = lambda: time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

# size caps for the DNS capture tables (enforced on insert; volume is tiny)
DNS_NAMES_MAX = 5000
DNS_EVENTS_MAX = 2000


def _row_to_rule(r: sqlite3.Row) -> Rule:
    return Rule(
        id=r["id"],
        policy_id=r["policy_id"],
        direction=r["direction"],
        proto=r["proto"],
        port=r["port"],
        port_end=r["port_end"],
        cidr=r["cidr"],
        dns=r["dns"],
        action=r["action"],
        enabled=bool(r["enabled"]),
        position=r["position"],
        comment=r["comment"],
        log=bool(r["log"]),
        created=r["created"],
    )


class Store:
    """Thread-safe SQLite wrapper. A single connection guarded by an RLock is
    sufficient for the write volumes of this app (logs + rare rule edits)."""

    def __init__(self, path: str):
        self.path = path
        self._lock = threading.RLock()
        self.conn = sqlite3.connect(path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        # DB is the source of truth: corruption refuses to start
        if not self.integrity_ok():
            raise RuntimeError(
                "SQLite database is corrupt — refusing to start "
                "(the DB is the source of truth)"
            )
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.execute("PRAGMA foreign_keys=ON")
        self.conn.execute("PRAGMA busy_timeout=5000")
        self._ensure_schema()
        self._migrate()

    # -- health -----------------------------------------------------------
    def integrity_ok(self) -> bool:
        try:
            with self._lock:
                row = self.conn.execute("PRAGMA integrity_check").fetchone()
                return row is not None and str(row[0]).lower() == "ok"
        except sqlite3.DatabaseError:
            return False

    def _ensure_schema(self) -> None:
        with self._lock:
            self.conn.executescript(SCHEMA)
            self.conn.commit()

    # -- policies ---------------------------------------------------------
    def get_or_create_policy(self, name: str) -> int:
        with self._lock:
            row = self.conn.execute("SELECT id FROM policies WHERE name=?", (name,)).fetchone()
            if row:
                return int(row["id"])
            cur = self.conn.execute(
                "INSERT INTO policies(name, created) VALUES(?,?)", (name, now_iso())
            )
            self.conn.commit()
            return int(cur.lastrowid)

    def list_policies(self) -> list[dict]:
        with self._lock:
            rows = self.conn.execute("SELECT * FROM policies ORDER BY name").fetchall()
            return [dict(r) for r in rows]

    def policy_name(self, policy_id: int | None) -> str | None:
        if policy_id is None:
            return None
        with self._lock:
            row = self.conn.execute("SELECT name FROM policies WHERE id=?", (policy_id,)).fetchone()
            return row["name"] if row else None

    # -- rules ------------------------------------------------------------
    def list_rules(self, policy_id: int | None = None, enabled_only: bool = False) -> list[Rule]:
        q = "SELECT * FROM rules"
        cond, args = [], []
        if policy_id is not None:
            cond.append("policy_id=?")
            args.append(policy_id)
        if enabled_only:
            cond.append("enabled=1")
        if cond:
            q += " WHERE " + " AND ".join(cond)
        q += " ORDER BY policy_id, position, id"
        with self._lock:
            return [_row_to_rule(r) for r in self.conn.execute(q, args).fetchall()]

    def get_rule(self, rule_id: int) -> Rule | None:
        with self._lock:
            r = self.conn.execute("SELECT * FROM rules WHERE id=?", (rule_id,)).fetchone()
            return _row_to_rule(r) if r else None

    def find_duplicate(self, policy_id: int, fields: dict,
                       exclude_id: int | None = None) -> Rule | None:
        """First rule in the policy with the same identity tuple (direction,
        proto, port, port_end, cidr, dns, action) — same semantics as preset
        idempotency. Comment/position/enabled/log are NOT part of identity."""
        key = (fields["direction"], fields["proto"], fields.get("port"),
               fields.get("port_end"), fields.get("cidr", ""),
               fields.get("dns", ""), fields["action"])
        for r in self.list_rules(policy_id):
            if r.id == exclude_id:
                continue
            if (r.direction, r.proto, r.port, r.port_end, r.cidr, r.dns, r.action) == key:
                return r
        return None

    def _migrate(self) -> None:
        """Lightweight in-place migrations for DBs created by older versions."""
        cols = {r[1] for r in self.conn.execute("PRAGMA table_info(rules)")}
        if "log" not in cols:
            self.conn.execute("ALTER TABLE rules ADD COLUMN log INTEGER NOT NULL DEFAULT 0")
        if "dns" not in cols:
            self.conn.execute("ALTER TABLE rules ADD COLUMN dns TEXT NOT NULL DEFAULT ''")
        self.conn.commit()

    def add_rule(self, policy_id: int, fields: dict) -> int:
        # defense for non-API write paths (import/presets): dns names are
        # normalized exactly like validate_rule does; empty stays empty
        fields = dict(fields)
        fields["dns"] = normalize_dns_name(str(fields.get("dns") or ""))
        with self._lock:
            pos = fields.get("position")
            if pos is None:
                pos = self.conn.execute(
                    "SELECT COALESCE(MAX(position),0)+1 FROM rules WHERE policy_id=?",
                    (policy_id,),
                ).fetchone()[0]
            cur = self.conn.execute(
                "INSERT INTO rules(policy_id, direction, proto, port, port_end, cidr,"
                " dns, action, enabled, position, comment, log, created)"
                " VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (
                    policy_id,
                    fields["direction"],
                    fields["proto"],
                    fields.get("port"),
                    fields.get("port_end"),
                    fields.get("cidr", ""),
                    fields.get("dns", ""),
                    fields["action"],
                    1 if fields.get("enabled", True) else 0,
                    pos,
                    fields.get("comment", ""),
                    1 if fields.get("log") else 0,
                    now_iso(),
                ),
            )
            self.conn.commit()
            return int(cur.lastrowid)

    def update_rule(self, rule_id: int, fields: dict) -> None:
        allowed = {"direction", "proto", "port", "port_end", "cidr", "dns", "action",
                   "enabled", "position", "comment", "log"}
        if "dns" in fields:  # normalize like add_rule ("" = clear the dns match)
            fields = dict(fields)
            fields["dns"] = normalize_dns_name(str(fields["dns"] or ""))
        cols, args = [], []
        for k, v in fields.items():
            if k not in allowed:
                continue
            cols.append(f"{k}=?")
            args.append(1 if v is True else 0 if v is False else v)
        if not cols:
            return
        args.append(rule_id)
        with self._lock:
            self.conn.execute(f"UPDATE rules SET {', '.join(cols)} WHERE id=?", args)
            self.conn.commit()

    def delete_rule(self, rule_id: int) -> bool:
        with self._lock:
            cur = self.conn.execute("DELETE FROM rules WHERE id=?", (rule_id,))
            self.conn.commit()
            return cur.rowcount > 0

    # -- containers -------------------------------------------------------
    def upsert_container(self, c: dict) -> None:
        import json

        ts = now_iso()
        with self._lock:
            self.conn.execute(
                "INSERT INTO containers(id, name, policy_id, ips, networks, state,"
                " host_network, self, first_seen, last_seen)"
                " VALUES(?,?,?,?,?,?,?,?,?,?)"
                " ON CONFLICT(id) DO UPDATE SET name=excluded.name,"
                " policy_id=excluded.policy_id, ips=excluded.ips,"
                " networks=excluded.networks, state=excluded.state,"
                " host_network=excluded.host_network, self=excluded.self,"
                " last_seen=excluded.last_seen",
                (
                    c["id"],
                    c["name"],
                    c.get("policy_id"),
                    json.dumps(c.get("ips", [])),
                    json.dumps(c.get("networks", [])),
                    c.get("state", ""),
                    1 if c.get("host_network") else 0,
                    1 if c.get("self") else 0,
                    ts,
                    ts,
                ),
            )
            self.conn.commit()

    def list_containers(self) -> list[dict]:
        import json

        with self._lock:
            rows = self.conn.execute("SELECT * FROM containers ORDER BY name").fetchall()
        out = []
        for r in rows:
            d = dict(r)
            d["ips"] = json.loads(d["ips"])
            d["networks"] = json.loads(d["networks"])
            d["host_network"] = bool(d["host_network"])
            d["self"] = bool(d["self"])
            out.append(d)
        return out

    def mark_gone_except(self, seen_ids: set[str]) -> None:
        """Flag containers no longer reported by docker (kept for log history)."""
        with self._lock:
            rows = self.conn.execute("SELECT id, state FROM containers").fetchall()
        for r in rows:
            if r["id"] not in seen_ids and r["state"] != "gone":
                with self._lock:
                    self.conn.execute(
                        "UPDATE containers SET state='gone' WHERE id=?", (r["id"],)
                    )
                    self.conn.commit()

    def get_container(self, cid: str) -> dict | None:
        """Resolve by full id, id prefix, or exact container name.
        Prefers exact ids, then running containers (recreated containers
        leave stale rows behind; logs stay attached to their ids)."""
        candidates = self.list_containers()
        for c in candidates:  # exact full id
            if c["id"] == cid:
                return c
        for c in candidates:  # name, running first
            if c["name"] == cid and c.get("state") == "running":
                return c
        for c in candidates:  # id prefix, running first
            if c["id"].startswith(cid) and c.get("state") == "running":
                return c
        for c in candidates:
            if c["name"] == cid or c["id"].startswith(cid):
                return c
        return None

    # -- logs -------------------------------------------------------------
    def insert_log(self, row: dict) -> int:
        with self._lock:
            cur = self.conn.execute(
                "INSERT INTO logs(ts, container_id, policy_id, dir, family, src, dst,"
                " proto, sport, dport, rule_id, ifaces)"
                " VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
                (
                    row.get("ts", int(time.time())),
                    row.get("container_id", ""),
                    row.get("policy_id"),
                    row.get("dir", ""),
                    row.get("family", 4),
                    row.get("src", ""),
                    row.get("dst", ""),
                    row.get("proto", ""),
                    row.get("sport"),
                    row.get("dport"),
                    row.get("rule_id"),
                    row.get("ifaces", ""),
                ),
            )
            self.conn.commit()
            return int(cur.lastrowid)

    def query_logs(
        self,
        container_id: str | None = None,
        direction: str | None = None,
        proto: str | None = None,
        port: int | None = None,
        since: int | None = None,
        limit: int = 200,
        offset: int = 0,
    ) -> list[dict]:
        q = "SELECT * FROM logs WHERE 1=1"
        args: list[Any] = []
        if container_id:
            q += " AND container_id=?"
            args.append(container_id)
        if direction in ("in", "out"):
            q += " AND dir=?"
            args.append(direction)
        if proto:
            q += " AND proto=?"
            args.append(proto.lower())
        if port is not None:
            q += " AND (dport=? OR sport=?)"
            args += [port, port]
        if since is not None:
            q += " AND ts>=?"
            args.append(since)
        q += " ORDER BY ts DESC, id DESC LIMIT ? OFFSET ?"
        args += [max(1, min(limit, 1000)), max(0, offset)]
        with self._lock:
            rows = self.conn.execute(q, args).fetchall()
        return [dict(r) for r in rows]

    def count_logs(self, container_id: str, hours: int = 24) -> int:
        since = int(time.time()) - hours * 3600
        with self._lock:
            row = self.conn.execute(
                "SELECT COUNT(*) FROM logs WHERE container_id=? AND ts>=?",
                (container_id, since),
            ).fetchone()
            return int(row[0])

    def blocked_counts(self, hours: int = 24) -> dict[str, int]:
        since = int(time.time()) - hours * 3600
        with self._lock:
            rows = self.conn.execute(
                "SELECT container_id, COUNT(*) AS n FROM logs WHERE ts>=? GROUP BY container_id",
                (since,),
            ).fetchall()
        return {r["container_id"]: int(r["n"]) for r in rows}

    def blocked_counts_by_dir(self, hours: int = 24) -> dict[tuple[str, str], int]:
        """Blocked attempts per (container, direction) — egress visibility."""
        since = int(time.time()) - hours * 3600
        with self._lock:
            rows = self.conn.execute(
                "SELECT container_id, dir, COUNT(*) AS n FROM logs WHERE ts>=?"
                " GROUP BY container_id, dir",
                (since,),
            ).fetchall()
        return {(r["container_id"], r["dir"]): int(r["n"]) for r in rows}

    def delete_rule_matching(self, policy_id: int, key: dict) -> int:
        """Delete rules identical to `key` (direction/proto/ports/cidr/action);
        used by preset removal. Returns number of rows deleted."""
        with self._lock:
            cur = self.conn.execute(
                "DELETE FROM rules WHERE policy_id=? AND direction=? AND proto=?"
                " AND COALESCE(port,-1)=COALESCE(?,-1)"
                " AND COALESCE(port_end,-1)=COALESCE(?,-1)"
                " AND cidr=? AND action=?",
                (
                    policy_id,
                    key["direction"],
                    key["proto"],
                    key.get("port"),
                    key.get("port_end"),
                    key.get("cidr", ""),
                    key["action"],
                ),
            )
            self.conn.commit()
            return int(cur.rowcount)

    # -- events -----------------------------------------------------------
    def add_event(self, kind: str, msg: str) -> None:
        with self._lock:
            self.conn.execute(
                "INSERT INTO events(ts, kind, msg) VALUES(?,?,?)",
                (int(time.time()), kind[:32], msg[:2000]),
            )
            self.conn.commit()

    def recent_events(self, limit: int = 100) -> list[dict]:
        with self._lock:
            rows = self.conn.execute(
                "SELECT * FROM events ORDER BY ts DESC, id DESC LIMIT ?", (limit,)
            ).fetchall()
        return [dict(r) for r in rows]

    # -- settings (runtime toggles) ------------------------------------------
    def get_setting(self, key: str, default: str = "") -> str:
        with self._lock:
            row = self.conn.execute(
                "SELECT value FROM settings WHERE key=?", (key,)
            ).fetchone()
            return row["value"] if row else default

    def get_bool_setting(self, key: str, default: bool = False) -> bool:
        val = self.get_setting(key)
        if val == "":
            return default
        return val in ("1", "true", "on", "yes")

    def set_settings(self, kv: dict[str, bool | int | str]) -> None:
        with self._lock:
            for k, v in kv.items():
                val = "1" if v is True else "0" if v is False else str(v)
                self.conn.execute(
                    "INSERT INTO settings(key, value) VALUES(?,?)"
                    " ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                    (k, val),
                )
            self.conn.commit()

    # -- dns answers (name <-> ip mapping) -----------------------------------
    def upsert_dns(self, name: str, ip: str, resolver: str = "", ts: int | None = None) -> bool:
        """Record one learned name<->ip mapping + a recent-answers event row.

        Returns True when the (name, ip) pair is NEW — i.e. the kernel set of
        any dns-rule referencing this name no longer matches the DB and a
        re-apply is needed (False = only freshness/hits were refreshed)."""
        ts = int(ts or time.time())
        with self._lock:
            row = self.conn.execute(
                "SELECT 1 FROM dns_names WHERE name=? AND ip=?", (name, ip)
            ).fetchone()
            new = row is None
            if new:
                self.conn.execute(
                    "INSERT INTO dns_names(name, ip, resolver, first_seen, last_seen, hits)"
                    " VALUES(?,?,?,?,?,1)",
                    (name, ip, resolver, ts, ts),
                )
            else:
                self.conn.execute(
                    "UPDATE dns_names SET resolver=?, last_seen=?, hits=hits+1"
                    " WHERE name=? AND ip=?",
                    (resolver, ts, name, ip),
                )
            self.conn.execute(
                "INSERT INTO dns_events(ts, resolver, name, ip) VALUES(?,?,?,?)",
                (ts, resolver, name, ip),
            )
            self._trim("dns_events", DNS_EVENTS_MAX, order="id")
            self._trim("dns_names", DNS_NAMES_MAX, order="last_seen")
            self.conn.commit()
            return new

    def dns_rule_names(self) -> set[str]:
        """Hostnames referenced by any ENABLED dns-rule (set expansion targets)."""
        with self._lock:
            rows = self.conn.execute(
                "SELECT DISTINCT dns FROM rules WHERE enabled=1 AND dns<>''"
            ).fetchall()
            return {r["dns"] for r in rows}

    def dns_ips(self, names: Iterable[str]) -> dict[str, dict[str, list[str]]]:
        """Observed answer IPs per name, split by family: {name: {'4': [...], '6': [...]}}.

        Name comparison is case-insensitive (dns capture stores names as seen
        in answers; rules normalize to lowercase)."""
        out: dict[str, dict[str, list[str]]] = {}
        with self._lock:
            for name in names:
                fams: dict[str, list[str]] = {"4": [], "6": []}
                for r in self.conn.execute(
                    "SELECT ip FROM dns_names WHERE name=? COLLATE NOCASE", (name,)
                ):
                    fams["6" if ":" in r["ip"] else "4"].append(r["ip"])
                out[name] = fams
        return out

    def _trim(self, table: str, cap: int, order: str = "id") -> None:
        self.conn.execute(
            f"DELETE FROM {table} WHERE rowid NOT IN"
            f" (SELECT rowid FROM {table} ORDER BY {order} DESC LIMIT ?)",
            (cap,),
        )

    def dns_mappings(self, q: str = "", limit: int = 1000) -> list[dict]:
        sql = "SELECT name, ip, resolver, first_seen, last_seen, hits FROM dns_names"
        args: list[Any] = []
        if q:
            sql += " WHERE name LIKE ? OR ip LIKE ?"
            like = f"%{q}%"
            args = [like, like]
        sql += " ORDER BY last_seen DESC LIMIT ?"
        args.append(max(1, min(limit, DNS_NAMES_MAX)))
        with self._lock:
            return [dict(r) for r in self.conn.execute(sql, args).fetchall()]

    def recent_dns_events(self, limit: int = 100) -> list[dict]:
        with self._lock:
            rows = self.conn.execute(
                "SELECT ts, resolver, name, ip FROM dns_events"
                " ORDER BY ts DESC, id DESC LIMIT ?",
                (max(1, min(limit, 1000)),),
            ).fetchall()
        return [dict(r) for r in rows]

    def dns_counts(self) -> dict[str, int]:
        with self._lock:
            names = self.conn.execute("SELECT COUNT(*) FROM dns_names").fetchone()[0]
            events = self.conn.execute("SELECT COUNT(*) FROM dns_events").fetchone()[0]
        return {"names": int(names), "events": int(events)}

    def name_for_ip(self, ip: str) -> str | None:
        with self._lock:
            row = self.conn.execute(
                "SELECT name FROM dns_names WHERE ip=? ORDER BY last_seen DESC LIMIT 1",
                (ip,),
            ).fetchone()
            return row["name"] if row else None

    def annotate_names(self, rows: list[dict]) -> list[dict]:
        """Add dst_name/src_name hints from the DNS mapping — the exfiltration
        view: 'dst 185.199.110.153' becomes '≈ raw.githubusercontent.com'."""
        ips = {r[k] for r in rows for k in ("dst", "src") if r.get(k)}
        if not ips:
            return rows
        marks = ",".join("?" * len(ips))
        with self._lock:
            found = {
                r["ip"]: r["name"]
                for r in self.conn.execute(
                    f"SELECT ip, name FROM dns_names WHERE ip IN ({marks})", list(ips)
                ).fetchall()
            }
        for r in rows:
            r["dst_name"] = found.get(r.get("dst"))
            r["src_name"] = found.get(r.get("src"))
        return rows

    def clear_dns(self) -> int:
        with self._lock:
            n = self.conn.execute("DELETE FROM dns_names").rowcount
            n += self.conn.execute("DELETE FROM dns_events").rowcount
            self.conn.commit()
            return n

    # -- retention ----------------------------------------------------------
    def prune_retention(self, days: int, max_rows: int, event_days: int) -> dict:
        """Retention by age and by size. days=0 disables age pruning,
        max_rows=0 disables size pruning (at least one should be set)."""
        now = int(time.time())
        stats = {"logs_age_deleted": 0, "logs_size_deleted": 0, "events_deleted": 0}
        with self._lock:
            if days:
                cutoff = now - days * 86400
                cur = self.conn.execute("DELETE FROM logs WHERE ts < ?", (cutoff,))
                stats["logs_age_deleted"] = cur.rowcount
            if max_rows:
                # exact size cap: delete everything beyond the newest max_rows
                cur = self.conn.execute(
                    "DELETE FROM logs WHERE id NOT IN"
                    " (SELECT id FROM logs ORDER BY id DESC LIMIT ?)",
                    (max_rows,),
                )
                stats["logs_size_deleted"] = cur.rowcount
            if event_days:
                cutoff = now - event_days * 86400
                cur = self.conn.execute("DELETE FROM events WHERE ts < ?", (cutoff,))
                stats["events_deleted"] = cur.rowcount
                cur = self.conn.execute("DELETE FROM dns_events WHERE ts < ?", (cutoff,))
                stats["events_deleted"] += cur.rowcount
            self.conn.commit()
        return stats

    # -- backup -------------------------------------------------------------
    def export_json(self) -> dict:
        policies = []
        for p in self.list_policies():
            rules = [r.to_json() for r in self.list_rules(policy_id=p["id"])]
            policies.append({"name": p["name"], "rules": rules})
        return {"version": 1, "policies": policies}

    def import_json(self, data: dict) -> int:
        """Upsert policies + rules from an export. Returns number of rules."""
        count = 0
        for p in data.get("policies", []):
            pid = self.get_or_create_policy(p["name"])
            for f in p.get("rules", []):
                fields = {
                    "direction": f.get("direction", "out"),
                    "proto": f.get("proto", "any"),
                    "port": f.get("port"),
                    "port_end": f.get("port_end"),
                    "cidr": f.get("cidr", "") or "",
                    "dns": f.get("dns", "") or "",
                    "action": f.get("action", "drop"),
                    "enabled": bool(f.get("enabled", True)),
                    "comment": f.get("comment", ""),
                }
                self.add_rule(pid, fields)
                count += 1
        return count

    def close(self) -> None:
        self.conn.close()
