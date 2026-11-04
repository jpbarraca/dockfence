# REST API reference

Base URL: `http://127.0.0.1:8420` (the bind address is `FW_LISTEN` — keep it on
localhost and use an SSH tunnel).

## Authentication

Every `/api/…` endpoint requires the token (`FW_TOKEN`):

```bash
curl -H "Authorization: Bearer $FW_TOKEN" http://127.0.0.1:8420/api/health
```

- Bearer header **or** the `fw_token` cookie (set by the WebUI login) **or**
  `?token=` query parameter.
- Unauthenticated API calls get `401 {"error":"unauthorized"}`; unknown paths
  `404 {"error":"not found"}`.
- Validation errors return `400 {"error": "…"}`; creating a rule identical to
  an existing one returns `409`.

## Containers & topology

| Endpoint | Description |
|----------|-------------|
| `GET /api/containers` | all containers: fw status (`opt_in`, tagged/untagged, host-network flag), policy, addresses, blocked 24 h counts |
| `GET /api/containers/{id}/rules` | rules of the container's policy; dns rules carry `dns_ips` (`{"4": [...], "6": [...]}`) |
| `GET /api/containers/{id}/logs` | blocked attempts; filters `direction`, `proto`, `port`, `since`; rows carry `src_name`/`dst_name` DNS hints |
| `GET /api/containers/{id}/sessions` | active conntrack sessions for the container (direction/proto/state/endpoints/ttl, incl. NAT'd inbound via published ports) |
| `GET /api/containers/{id}/counters` | live per-rule packet/byte counters (read from in-kernel nftables counters on demand) |
| `POST /api/containers/{id}/flush` | conntrack flush helper: deletes the host's tracked entries for the container's IPs so pending rule changes re-evaluate established flows immediately → `{"available", "deleted", "ips", "errors"}` (needs the `conntrack` binary) |
| `GET /api/edges` | live connection edges aggregated to container↔container / container↔outside for the topology view (read-only) |

`{id}` accepts the container id, short id, or name.

## Rules

```bash
# create — remote side is cidr OR dns, never both
curl -X POST -H "Authorization: Bearer $FW_TOKEN" -H "Content-Type: application/json" \
  -d '{"direction":"out","proto":"tcp","port":443,"cidr":"203.0.113.4/32","action":"accept",
       "comment":"github api"}' \
  http://127.0.0.1:8420/api/containers/<id>/rules

# or by DNS name (IPs learned from the DNS answer capture):
curl -X POST … -d '{"direction":"out","proto":"tcp","port":443,"dns":"example.com","action":"accept"}' …

# enable/disable/edit (partial):
curl -X PATCH … http://127.0.0.1:8420/api/rules/<rule_id> -d '{"enabled":false}'

# remove:
curl -X DELETE http://127.0.0.1:8420/api/rules/<rule_id>
```

Payload fields: `direction` (`in`/`out`), `proto` (`tcp`/`udp`/`icmp`/`any`),
`port`, `port_end` (optional), `cidr` **or** `dns` (FQDN; sent together → 400),
`action` (`accept`/`drop`), `comment`, `log`, `enabled`, `position`.
`tcp`/`udp` require a dport; `any` with a dport matches both tcp and udp.
Duplicates (same `direction, proto, port, port_end, cidr, dns, action`) → 409.
The response is the created/updated rule JSON.

## Presets

| Endpoint | Description |
|----------|-------------|
| `GET /api/presets` | catalog (harden-egress, dns-out, ntp-out, web-out, icmp-out, deny-private-out, allow-any-out) |
| `POST /api/containers/{id}/presets/{name}` | apply a preset (idempotent) |
| `DELETE /api/containers/{id}/presets/{name}` | remove exactly that preset's rules |

## Settings, DNS & logs

| Endpoint | Description |
|----------|-------------|
| `GET /api/settings` | `{"logging": bool, "dns_log": bool}` — both default `false` |
| `PATCH /api/settings` | toggle packet logging / DNS capture (re-renders the kernel table) |
| `GET /api/dns[?q=]` | learned name ↔ ip mappings (optional filter) |
| `GET /api/dns/recent` | recent DNS answers (name, ip, resolver) |
| `DELETE /api/dns` | forget all learned mappings |
| `GET /api/logs/stream` | SSE live tail of blocked attempts (optional `?container=<id>&max_events=N`) |
| `GET /api/events` | recent service events (`?limit=`, default 100) |

## Operations

| Endpoint | Description |
|----------|-------------|
| `GET /api/health` | mode, apply status (`last_apply_ok`, `apply_failures`), nflog/docker/db status |
| `GET /api/metrics` | Prometheus counters (`dfw_blocked_24h{direction=…}`, …) |
| `POST /api/resync` | force reconcile (re-render + atomic apply) |
| `GET /api/export` | backup: all policies + rules as JSON |
| `POST /api/import` | restore: `{"version": …, "policies": [...]}` → re-applies the table |

## Web pages

| Path | Page |
|------|------|
| `/login` | token login (sets the `fw_token` cookie) |
| `/` | topology + blocked 24 h |
| `/containers/<id>` | per-container rules/logs/presets/sessions/counters + allow dialog |
| `/dns` | learned mappings |
| `/health` | health view |
