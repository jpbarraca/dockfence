# Security model & known caveats

## What dockfence protects

For every container that **opts in** with the label:

- **default-deny egress** — the container may only talk to destinations its
  policy explicitly allows; a compromised container cannot phone home or pivot
  into the LAN unless a rule allows it;
- **default-deny ingress** — inbound flows to the container are dropped unless
  allowed (published ports keep working via Docker's DNAT, which is accepted
  as established/related or via the ingress rules you add);
- **deny-private-out backstop** — private-range egress drops even when a
  broad allow is added later;
- **visibility** — every blocked attempt is (rate-limited) logged with
  DNS-name hints, browsable per container.

Untagged containers are untouched; Docker's own tables are never modified.

## Trust boundaries & privileges

The dockfence container runs with `network_mode: host` and `CAP_NET_ADMIN` —
the minimum needed to program the **host's** nftables and consume nflog
netlink messages — and a **read-only** docker socket. It only ever creates its
own `table inet dockfence`; Docker's tables are neither read nor written.

The API/UI token (`FW_TOKEN`) is the single credential for everything: API and
WebUI. The service binds to `127.0.0.1` by default — reach it via SSH tunnel.
Where the UI must be reached over an untrusted link, serving HTTPS with
`FW_TLS_CERT`/`FW_TLS_KEY` protects the transport (the token still gates the
application). An auto-generated token is printed to the container log at
startup; never run with a guessable token on a multi-user host. There is no
unauthenticated write path.

## Known caveats (by design)

- **Docker embedded DNS (127.0.0.11) bypasses the firewall** (the daemon
  proxies from the host netns). Direct DNS (e.g. 8.8.8.8) *is* blocked.
  **Exfiltration-relevant:** a container can encode data into DNS queries
  towards the host's upstream resolver; those queries leave via the host
  netns and are invisible to this firewall. Mitigate by running a filtering
  resolver as an allow-listed destination and pointing container DNS at it,
  or accept the residual risk.
- **DoH/DoT is invisible to the DNS answer capture** (plain DNS, port 53
  responses only). DNS-based rules cannot follow names a container resolves
  over HTTPS.
- **DNS mappings are global**, not per container: Docker's embedded resolver
  hides per-container queries, so a `dns` rule holds every IP observed for the
  name across all tagged containers.
- **An unobserved name matches nothing** (fail-closed): a `dns` accept rule
  allows no traffic until the capture has seen the name resolve. Keep the
  `dns` capture toggle on or sets freeze at their last known state.
- **localhost-published ports** arrive with src = bridge gateway → the
  ingress preset adds the gateway CIDR.
- **Pre-existing conntrack flows keep flowing** until they die; tag containers
  at creation time, not after they have traffic. To close an existing flow
  anyway, use the conntrack flush helper (`POST /api/containers/{id}/flush`
  or the button on the container page) — it deletes the container's tracked
  entries so the next packet is re-evaluated by the current ruleset.
- **Host-network containers are unfilterable** (no veth) — flagged in the UI.
- **Rootless Docker is unsupported** (needs `CAP_NET_ADMIN` in the init
  network namespace).
- **ARP/L2 is not filtered** — IP flows only; IPv6 is flag-gated
  (`FW_IPV6=true`) on the same `inet` table.
- **nflog queue pressure drops log lines, never enforcement** — under load
  some blocked attempts may be missing from the logs while the kernel still
  drops everything.

## Disclosure posture

dockfence is a host firewall, not a sandbox: a container with a broad allow
rule has exactly the access that rule grants. Review rules after incident
investigation, prefer `harden-egress` + narrow accepts, and check the
counters/logs for rule usage.
