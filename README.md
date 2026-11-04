<div align="center">

# dockfence

**A default-deny nftables firewall for labelled Docker containers — itself run as a Docker container.**

Opt-in per container · coexists with Docker's own firewall · WebUI included ·
DNS-aware rules · anti-exfiltration presets

![License: GPL-3.0-or-later](https://img.shields.io/badge/license-GPL--3.0--or--later-blue.svg)
![Python](https://img.shields.io/badge/python-3.11%2B-blue.svg)
![Platform](https://img.shields.io/badge/platform-linux-lightgrey.svg)

</div>

---

Every container carrying the `dockfence` label lands behind a **default-deny**
firewall: no ingress, no egress. All blocked attempts are logged (rate-limited)
and browsable per container in a WebUI on `127.0.0.1:8420`. Untagged containers
are untouched.

Implemented in Python (Flask API/WebUI, official docker SDK, pure-Python netlink
NFLOG consumer, `nft -f` for atomic table applies). The design details live in
[`docs/architecture.md`](docs/architecture.md).

```
dockerd ── docker.sock (ro) ──► dockfence container (host net, CAP_NET_ADMIN)
    watcher → reconciler → nft compiler/applier ──► table inet dockfence   ← ours only
    nflog consumer ──► SQLite (rules, logs) ◄── REST API + WebUI
```

## Highlights

- **Opt-in, default-deny** — add a label, get a firewall; remove it, get your
  container back. Everything Docker already does keeps working.
- **Plays along with Docker** — lives in its *own* nftables table, never reads
  or modifies Docker's tables/chains; survives `systemctl restart docker`.
- **Kernel is a projection** — the table is regenerated from SQLite and applied
  as one atomic `nft -f` batch; a failed apply keeps the last good kernel state;
  a corrupt DB refuses to apply anything (fail-closed).
- **WebUI** — topology, per-container rules, blocked-attempt logs, live
  conntrack sessions, per-rule packet/byte counters, one-click "allow" from a
  blocked log row.
- **DNS-based rules** — allow a hostname instead of a CIDR; a kernel set of the
  IPs the DNS answer capture observed for that name follows the host around
  (fail-closed when a name was never observed).
- **Anti-exfiltration presets** — `deny-private-out` backstop drops egress into
  private ranges even when a broad allow exists later.
- **Observable** — Prometheus metrics, SSE live tail, per-rule counters, live
  edges view. Backup/restore of all rules as JSON.

## Quick start

```bash
git clone https://github.com/<you>/dockfence && cd dockfence
sudo bash scripts/survey.sh            # environment survey first
sudo docker compose up -d --build
sudo docker compose logs dockfence | grep -i token   # UI/API token (or set FW_TOKEN)
```

The UI binds to `127.0.0.1` only — open it through an SSH tunnel:

```bash
ssh -L 8420:127.0.0.1:8420 root@<host>
# → http://127.0.0.1:8420
```

Opt a container in with a label:

```yaml
services:
  web:
    labels:
      dockfence: ""            # opt-in; policy name = container name
      # dockfence.policy: shared   # optional: shared policy across containers
```

## Modes

| `FW_MODE`    | Behaviour                                                            |
|--------------|----------------------------------------------------------------------|
| `enforcing`  | default-deny for tagged containers (default)                          |
| `monitor`    | identical chains, everything logged **and accepted** — recommended first rollout |
| `disabled`   | table removed, no filtering                                           |

## Rules & presets

Rules are `direction` (`in`/`out`) × `proto` (`tcp`/`udp`/`icmp`/`any`) ×
optional dport × remote side (`cidr` **or** `dns` name) × `action`
(`accept`/`drop`). `ct state established,related` is accepted on top, so return
traffic of allowed flows just works. `any` with a dport matches both tcp and
udp — "allow DNS out" is one rule, not two.

One-click **presets** (container page, or
`POST /api/containers/{id}/presets/{name}`):

| Preset              | Rules                                                                 |
|---------------------|-----------------------------------------------------------------------|
| `harden-egress`     | DNS + NTP + web + ICMP out, **and** deny-private-out (recommended)    |
| `dns-out`           | UDP+TCP 53 accept                                                     |
| `ntp-out`           | UDP 123 accept                                                        |
| `web-out`           | TCP 80,443 accept (broad — pair with deny-private-out)                |
| `icmp-out`          | ICMP/ICMPv6 accept (PMTU)                                             |
| `deny-private-out`  | **drop** egress into `10/8, 172.16/12, 192.168/16, 127/8, 169.254/16, 100.64/10, fc00::/7, fe80::/10, ::1/128` — logged, inserted *before* all other rules |
| `allow-any-out`     | accept any egress (explicitly disables egress protection)             |

`deny-private-out` is the exfiltration backstop: even if a broad allow is added
later, traffic into private ranges is still dropped first. Deny drops are
logged (rate-limited), so attempts stay visible.

### DNS-based rules (hostname match from observed DNS answers)

A rule's remote side is matched by **cidr OR `dns` name** (never both). A `dns`
rule keeps a kernel-side nftables set of every IP the DNS answer capture has
observed for that hostname:

```bash
curl -X POST -H "Authorization: Bearer $FW_TOKEN" -H "Content-Type: application/json" \
  -d '{"direction":"out","proto":"tcp","port":443,"dns":"example.com","action":"accept"}' \
  http://127.0.0.1:8420/api/containers/<id>/rules
```

- the capture learns `name ↔ ip` from DNS answers delivered to tagged
  containers (CNAME chains included, so alias names work);
- a **new** IP for a referenced name re-applies the table (debounced ~2 s) and
  the set picks it up;
- exact names only; mappings are global (Docker's embedded resolver hides
  per-container queries);
- an unobserved name renders an **empty set → the rule matches nothing**
  (fail-closed). Keep the `dns` capture toggle on, or the sets freeze at their
  last known state.

## Logging & DNS answer capture (UI toggles — off by default)

Both features are **disabled by default** and toggled in the UI header
(`PATCH /api/settings`):

- **`log`** — packet logs: rate-limited NFLOG records of blocked attempts (and
  deny-preset drops). Off ⇒ nothing recorded, blocked tables stay empty.
- **`dns`** — DNS answer capture: passive chains mirror DNS responses delivered
  to tagged containers (plus replies from Docker's embedded resolver) into a
  learned **name ↔ IP mapping** — shown on the DNS page and attached as hints
  (`≈ name`) to blocked-log endpoints, powering the allow dialog's
  "by DNS name" choice and the `dns` rule sets.

## Configuration (env)

| Variable                 | Default          | Meaning                                        |
|--------------------------|------------------|------------------------------------------------|
| `FW_LABEL`               | `dockfence`      | opt-in label key                               |
| `FW_MODE`                | `enforcing`      | `enforcing` / `monitor` / `disabled`           |
| `FW_LISTEN`              | `127.0.0.1:8420` | API/UI bind (localhost; use SSH tunnel)        |
| `FW_TOKEN`               | auto-generated   | UI/API token (printed to logs if empty)        |
| `FW_TLS_CERT` / `FW_TLS_KEY` | unset        | serve the WebUI/API over HTTPS (PEM cert+key; both required) |
| `FW_FILTER_HOST`         | `true`           | also filter container → host via egress rules  |
| `FW_LOG_GROUP`           | `5`              | nfnetlink log group; DNS capture uses group+1  |
| `FW_LOG_LIMIT`           | `10/second`      | log rate (burst = 2×rate)                      |
| `FW_RECONCILE`           | `30s`            | drift-correction loop                          |
| `FW_RETENTION_DAYS`      | `30`             | log pruning by **age** (0 = off)               |
| `FW_RETENTION_MAX_ROWS`  | `500000`         | log pruning by **size** (0 = off)              |
| `FW_EVENT_RETENTION_DAYS`| `7`              | event table pruning                            |
| `FW_IPV6`                | `false`          | IPv6 filtering on the same `inet` table        |
| `FW_DB`                  | `/var/lib/dockfence/dockfence.db` | SQLite path                  |

## API

All endpoints need `Authorization: Bearer <token>` (the UI uses a cookie).
Full reference: [`docs/api.md`](docs/api.md).

```bash
curl -H "Authorization: Bearer $FW_TOKEN" http://127.0.0.1:8420/api/containers
curl -H "Authorization: Bearer $FW_TOKEN" http://127.0.0.1:8420/api/health
curl -H "Authorization: Bearer $FW_TOKEN" http://127.0.0.1:8420/api/presets
```

## Documentation

| Document                                      | Contents                                           |
|-----------------------------------------------|----------------------------------------------------|
| [`docs/architecture.md`](docs/architecture.md) | components, chain design, apply lifecycle, DNS capture internals |
| [`docs/api.md`](docs/api.md)                   | REST API reference                                 |
| [`docs/deployment.md`](docs/deployment.md)     | production rollout, upgrades, backup/restore, monitoring |
| [`docs/security.md`](docs/security.md)         | threat model, auth model, known caveats & residual risks |

## Development

```bash
python3 -m venv venv && venv/bin/pip install -r requirements.txt -e .[dev]
venv/bin/python -m pytest tests -q          # unit: renderer golden, nflog parse, store, API
sudo bash scripts/test.sh                   # integration on a Docker host
```

Layout: `dockfence/` (config, models, store, nft renderer/applier, watcher,
nflog consumer, controller, retention, api + `web/` templates/static),
`scripts/` (survey, integration tests), `tests/golden/` (nft fixtures).

## License

Copyright © 2026 the dockfence authors.

This program is free software: you can redistribute it and/or modify it under
the terms of the **GNU General Public License as published by the Free Software
Foundation, version 3** — see [`LICENSE`](LICENSE). There is no warranty; use
at your own risk.
