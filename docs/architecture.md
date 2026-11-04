# Architecture

How dockfence works: the components, the nftables design, the apply lifecycle,
and the DNS answer capture that powers DNS-based rules.

```
┌────────────────────────── host ──────────────────────────┐
│  dockerd ─── /var/run/docker.sock (mounted read-only)    │
│      │  events (start/die/destroy/restart,                │
│      │  network connect/disconnect) + inspect            │
│      ▼                                                    │
│  ┌───────── dockfence container (network_mode: host) ──┐ │
│  │ docker watcher → reconciler → nft compiler/applier  │ │
│  │ nflog consumer → SQLite (policies, rules, logs)     │ │
│  │ REST API + WebUI  (default 127.0.0.1:8420)          │ │
│  └─────────────────────────────────────────────────────┘ │
│         ▲ nfnetlink/nflog            │ nft -f (atomic)   │
│         └────── table inet dockfence ◄── ours only       │
└──────────────────────────────────────────────────────────┘
```

## Components

| Module            | Role                                                                 |
|-------------------|----------------------------------------------------------------------|
| `watcher.py`      | Docker events + inspect: container/network lifecycle, label opt-in    |
| `controller.py`   | Reconciler: renders the table from the store and applies it; drift correction loop (`FW_RECONCILE`) |
| `nft.py`          | Pure renderer (`render_table` → `nft -f` text) + `NftApplier` (one atomic batch) |
| `nflog.py`        | Pure-Python netlink NFLOG consumer: blocked-attempt logs, DNS answer capture, debounced rules-changed trigger |
| `store.py`        | SQLite: policies, rules, blocked logs, dns_names/dns_events, settings; source of truth |
| `conntrack.py`    | Live sessions/edges from procfs or the `conntrack` binary; flush helper deletes a container's entries |
| `presets.py`      | Catalog of one-click rule bundles (incl. `deny-private-out`)          |
| `retention.py`    | Pruning by age and size for logs/events/dns tables                    |
| `api.py`          | Flask: REST API + WebUI (`web/templates`, `web/static`)               |
| `models.py`       | Rule/Policy/Container models, validation (incl. cidr XOR dns)         |
| `config.py`       | Env config, token generation                                          |

## nftables design

- One self-owned `table inet dockfence`; base chains hook **forward/input at
  priority filter+10** with `policy accept` — we only ever *subtract* from what
  Docker's own firewall already accepted, and never touch Docker's tables
  (survives `systemctl restart docker`).
- Per container: `c_<shortid>_out` / `c_<shortid>_in` chains. Every rule is a
  match + `counter accept`; the chain ends with a **terminal pair** — a
  rate-limited `log group 5` rule and then `counter drop`. `limit` is a
  *match*, so a single `limit … drop` would leak burst traffic — the pair
  never does. With the `log` toggle off the terminal pair is just
  `counter drop` and no NFLOG rule exists anywhere.
- `ct state established,related accept` on top passes return traffic of allowed
  flows.
- Rule protos: `tcp`/`udp` need a dport; `icmp` has none; **`any` with a dport
  matches both tcp and udp** (`meta l4proto { tcp, udp } th dport N`).
- Kernel comments `r#<id>|<comment>` tie every rendered line back to its rule
  row; per-rule counters power the live counters view.

### Remote-side matching: cidr or DNS name

A rule matches the remote side by **cidr OR dns name, never both** (enforced at
validation and mirrored in the UI). For a `dns` rule the renderer emits, per
address family, a match against a named set:

```
ip daddr @dns<id>  tcp dport 443 counter accept comment "r#<id>"
ip6 daddr @dns<id>6 …                              (only with FW_IPV6=true)
```

The set's elements are the IPs observed for that hostname (see below). An
**empty set = fail-closed**: the rule matches nothing until the name has
actually been resolved.

### Apply lifecycle (kernel is a projection)

1. Everything that can change the table (rule CRUD, container events, settings
   toggles, new DNS pairs for a referenced name) funnels into
   `controller.rules_changed` / the reconcile loop.
2. The controller renders the **whole table** from SQLite and applies it as
   **one atomic `nft -f` batch** — there is no incremental kernel editing.
3. A failed apply keeps the last good kernel state; `apply_failures` is
   reported on `/api/health`. A corrupt DB refuses to apply anything.
4. The reconcile loop re-renders periodically to correct drift (e.g. someone
   flushed the table manually).

## DNS answer capture

Both capture features are off by default (`/api/settings`); toggling re-renders
the table.

- **Packet logs (`log`)** — the rate-limited NFLOG terminal pairs (blocked
  attempts) and log-and-continue lines of deny presets are only rendered while
  on. The consumer parses them into per-container blocked logs with DNS hints.
- **DNS capture (`dns`)** — passive chains `dfw_dns_fwd` (forward hook) and
  `dfw_dns_out` (output hook, nflog group `FW_LOG_GROUP+1`) mirror every DNS
  response (udp/tcp source port 53) *delivered to a tagged container's IP*,
  plus replies from Docker's embedded resolver (source 127.0.0.11). The host's
  own lookups are deliberately not captured.

Why forward+output: Docker DNATs a container's query to the upstream resolver
**while preserving the container's source IP**, so the answer comes back
through FORWARD addressed to the container — attributable per container
(verified live with a temporary nft counter probe). Replies from the embedded
resolver itself (src 127.0.0.11) are covered on the output hook as a defensive
fallback. With no tagged containers there are no dns chains at all.

The consumer parses A/AAAA/CNAME (compression pointers supported) into a
learned **name ↔ IP mapping** (`dns_names` / `dns_events` tables, capped):

- CNAME chains are followed, so alias names resolve to the address IPs;
- mappings are **global**, not per container (the embedded resolver hides
  per-container queries); exact names only, no wildcards;
- when a **new** `(name, ip)` pair is learned for a name referenced by an
  enabled dns-rule, the nflog consumer flags it and a dedicated thread drains
  pending names every 2 s → `controller.rules_changed` (debounced, off the
  packet path) → the table re-applies and the kernel set picks up the IP;
- with the capture off, no new pairs are learned ⇒ sets freeze at their last
  known state (the UI warns).

The mapping powers: the DNS page, `≈ name` hints on blocked-log endpoints, the
allow-from-log dialog's "by DNS name" choice, and the `dns` rule sets.

## Store (source of truth)

SQLite (`FW_DB`, mounted at `/var/lib/dockfence`): policies (one per tagged
container, or shared via the `dockfence.policy` label), rules (identity tuple
`direction, proto, port, port_end, cidr, dns, action` → duplicates rejected),
blocked-attempt logs, dns_names/dns_events, settings, events. Retention prunes
by age and size. Export/import (`/api/export`, `/api/import`) round-trips all
policies + rules as JSON.

## WebUI pages

| Page                | Contents                                                          |
|---------------------|-------------------------------------------------------------------|
| `/` (topology)      | live container/network/internet topology from `/api/edges`, blocked 24 h |
| `/containers/<id>`  | fw status, rules (incl. observed dns IPs), blocked-connection logs with allow dialog, presets, live conntrack sessions, per-rule counters |
| `/dns`              | learned name ↔ IP mappings, recent answers, forget-all            |
| `/health`           | health/apply status                                               |

The **allow** button on a blocked-log row opens a prefilled dialog: match the
remote side **by IP (cidr)** or **by DNS name** (prefilled from the capture's
`≈ name` annotation; disabled when no name was observed — a made-up name would
match nothing due to fail-closed empty sets).
