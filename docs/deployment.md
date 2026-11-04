# Deployment & operations

## Requirements

- Linux host with **nftables** (kernel ≥ 5.x, nft binary ≥ 1.0) and Docker
  ≥ 20; rootless Docker and host-network containers are not supported targets.
- The dockfence container needs: `network_mode: host`, `CAP_NET_ADMIN`, the
  docker socket mounted read-only, and a persistent volume for SQLite
  (`./data:/var/lib/dockfence`) — see the shipped `compose.yaml`.

## First rollout

1. **Survey the host** (validates hook/priority/nflog assumptions):
   ```bash
   sudo bash scripts/survey.sh
   ```
2. **Start in monitor mode** (recommended): set `FW_MODE: monitor` in
   `compose.yaml`, then
   ```bash
   sudo docker compose up -d --build
   sudo docker compose logs dockfence | grep -i token
   ```
   Monitor renders the identical chains but accepts everything — watch the
   WebUI to see what *would* be blocked.
3. **Set a token** (`FW_TOKEN` in compose.yaml — never run with the default on
   an exposed host) and confirm the UI over an SSH tunnel:
   ```bash
   ssh -L 8420:127.0.0.1:8420 root@<host>
   # → http://127.0.0.1:8420
   ```
4. **Switch to enforcing** and opt containers in one by one with the
   `dockfence` label. Start with `harden-egress` on each container, then add
   specific rules as the blocked-attempt logs show what's missing.

## TLS

The WebUI/API is plain HTTP on localhost by default — reach it through an SSH
tunnel. To serve HTTPS directly (e.g. when exposing the UI on a management
interface), point `FW_TLS_CERT`/`FW_TLS_KEY` at PEM files mounted read-only:

```yaml
    volumes:
      - ./certs:/certs:ro
    environment:
      FW_TLS_CERT: /certs/dockfence.crt
      FW_TLS_KEY: /certs/dockfence.key
```

Both variables are required together (startup refuses half a TLS config). The
token stays mandatory — TLS protects the transport, not the application.

## Upgrades

```bash
git pull                       # or rsync your checkout to the host
sudo docker compose up -d --build
curl -s -H "Authorization: Bearer $FW_TOKEN" http://127.0.0.1:8420/api/health
```

`/api/health` should read `mode: enforcing`, `last_apply_ok: true`,
`apply_failures: 0`. Rules live in SQLite, so container recreation keeps every
policy and rule.

## Backup & restore

```bash
curl -s -H "Authorization: Bearer $FW_TOKEN" http://127.0.0.1:8420/api/export > fw-backup.json
curl -s -X POST -H "Authorization: Bearer $FW_TOKEN" -H "Content-Type: application/json" \
  -d @fw-backup.json http://127.0.0.1:8420/api/import
```

Import validates every rule and re-applies the table atomically. The SQLite
file itself also snapshots fine (`data/dockfence.db`) while the service is
stopped.

## Monitoring

- `/api/health` — apply failures, nflog binding, docker/db status; wire it
  into your uptime checker (it requires the token).
- `/api/metrics` — Prometheus counters (blocked attempts by direction, apply
  status, nflog drops).
- `/api/logs/stream` (SSE) — live tail of blocked attempts.

## Retention

Logs are pruned by age (`FW_RETENTION_DAYS`), size (`FW_RETENTION_MAX_ROWS`)
and event age (`FW_EVENT_RETENTION_DAYS`); set `0` to disable a dimension.
The DNS mapping tables are capped separately.

## Teardown

```bash
# set FW_MODE: "disabled" in compose.yaml, then recreate so the table is removed:
sudo sed -i 's/FW_MODE: enforcing/FW_MODE: disabled/' compose.yaml
sudo docker compose up -d
sudo docker compose down
```

Untagged containers were never touched; tagged containers lose their rules
when the table goes away. Docker's own firewall is never modified, so
published ports keep working throughout.
