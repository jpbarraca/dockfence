"""One-click egress presets, incl. anti-exfiltration.

The firewall's baseline already default-DENIES egress for every tagged
container (per-container `c_<id>_out` chains). Presets add the
commonly needed allow rules — and, crucially for exfiltration defence,
`deny-private-out` inserts DROP rules BEFORE any existing rules so that
broad allows (cidr 'any') can never leak traffic into private/internal
ranges. Deny rules carry the `log` flag so blocked exfiltration attempts
are still visible in the NFLOG tail (rate-limited).

Exceptions to the deny list are made by adding a specific accept rule and
lowering its position below the deny rules (PATCH /api/rules/<id>).
"""

from __future__ import annotations

from .models import validate_rule
from .store import Store


def _r(direction: str, proto: str, port: int | None = None,
       cidr: str = "", action: str = "accept", comment: str = "",
       log: bool = False) -> dict:
    return {
        "direction": direction,
        "proto": proto,
        "port": port,
        "port_end": None,
        "cidr": cidr,
        "action": action,
        "comment": comment,
        "log": log,
    }


_PRIVATE_OUT = [
    _r("out", "any", cidr=c, action="drop", log=True,
       comment="preset: deny private out")
    for c in (
        "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",   # RFC1918
        "127.0.0.0/8", "169.254.0.0/16", "100.64.0.0/10",  # loopback/link-local/CGNAT
        "fc00::/7", "fe80::/10", "::1/128",                # IPv6 ULA/link-local/loopback
    )
]

CATALOG: dict[str, dict] = {
    "harden-egress": {
        "label": "harden egress (recommended)",
        "description": "One click: allow DNS, NTP, web and ICMP out; deny all "
                       "egress into private ranges (anti-exfiltration).",
        "compose": ["dns-out", "ntp-out", "web-out", "icmp-out", "deny-private-out"],
        "rules": [],
    },
    "dns-out": {
        "label": "allow DNS out",
        "description": "UDP+TCP 53 to any destination. Note: Docker's embedded "
                       "DNS (127.0.0.11) bypasses this firewall entirely — see README.",
        "rules": [
            _r("out", "udp", port=53, comment="preset: DNS out (udp)"),
            _r("out", "tcp", port=53, comment="preset: DNS out (tcp)"),
        ],
    },
    "ntp-out": {
        "label": "allow NTP out",
        "description": "UDP 123 to any destination.",
        "rules": [_r("out", "udp", port=123, comment="preset: NTP out (udp)")],
    },
    "web-out": {
        "label": "allow web out",
        "description": "HTTP+HTTPS (TCP 80,443) to any destination. Broad allow: "
                       "pair with 'deny private ranges out'.",
        "rules": [
            _r("out", "tcp", port=80, comment="preset: web out (http)"),
            _r("out", "tcp", port=443, comment="preset: web out (https)"),
        ],
    },
    "icmp-out": {
        "label": "allow ping/PMTU out",
        "description": "ICMP + ICMPv6 egress (PMTU discovery needs this once "
                       "web-out is enabled).",
        "rules": [_r("out", "icmp", comment="preset: icmp out")],
    },
    "deny-private-out": {
        "label": "deny private ranges out (anti-exfiltration)",
        "description": "DROP egress into RFC1918/loopback/link-local/CGNAT and "
                       "IPv6 ULA. Inserted BEFORE other rules: broad allows "
                       "added later cannot leak into internal networks. To "
                       "except a host (e.g. internal DNS), add an accept rule "
                       "and lower its position below these.",
        "first": True,
        "rules": _PRIVATE_OUT,
    },
    "allow-any-out": {
        "label": "allow ANY egress (disables egress protection)",
        "description": "Accept all egress. Explicit opt-out of egress "
                       "filtering for this policy.",
        "rules": [_r("out", "any", action="accept", comment="preset: allow any egress")],
    },
}

# validate once at import: a bad preset is a programmer error, not runtime data
for _spec in CATALOG.values():
    _spec["rules"] = [validate_rule(r, partial=False) for r in _spec["rules"]]


def _key(direction: str, proto: str, port, port_end, cidr: str, action: str) -> tuple:
    return (direction, proto, port, port_end, cidr, action)


def _spec_key(rule: dict) -> tuple:
    return _key(rule["direction"], rule["proto"], rule["port"],
                rule["port_end"], rule["cidr"], rule["action"])


def _rule_key(r) -> tuple:
    return _key(r.direction, r.proto, r.port, r.port_end, r.cidr, r.action)


def apply_preset(store: Store, policy_id: int, name: str) -> dict:
    """Add a preset's rules to a policy. Idempotent: rules identical to an
    existing one are skipped. 'deny-private-out' rules are front-inserted."""
    spec = CATALOG.get(name)
    if spec is None:
        raise KeyError(name)
    if spec.get("compose"):
        added: list[dict] = []
        skipped = 0
        for sub in spec["compose"]:
            res = apply_preset(store, policy_id, sub)
            added.extend(res["added"])
            skipped += res["skipped"]
        return {"preset": name, "added": added, "skipped": skipped}

    existing = store.list_rules(policy_id)
    have = {_rule_key(r) for r in existing}
    front = bool(spec.get("first"))
    base = 0
    if front:
        positions = [r.position for r in existing]
        # insert as a block before the current minimum position
        base = min(positions) - len(spec["rules"]) if positions else 0
    added, skipped = [], 0
    for i, fields in enumerate(spec["rules"]):
        if _spec_key(fields) in have:
            skipped += 1
            continue
        f = dict(fields)
        if front:
            f["position"] = base + i
        rule_id = store.add_rule(policy_id, f)
        added.append(store.get_rule(rule_id).to_json())
    return {"preset": name, "added": added, "skipped": skipped}


def delete_preset(store: Store, policy_id: int, name: str) -> int:
    """Remove rules identical to a preset's rules (composite presets recurse)."""
    spec = CATALOG.get(name)
    if spec is None:
        raise KeyError(name)
    if spec.get("compose"):
        return sum(delete_preset(store, policy_id, sub) for sub in spec["compose"])
    return sum(store.delete_rule_matching(policy_id, f) for f in spec["rules"])


def catalog_json() -> list[dict]:
    return [
        {
            "name": name,
            "label": spec["label"],
            "description": spec["description"],
            "compose": spec.get("compose", []),
            "rules": spec["rules"],
        }
        for name, spec in CATALOG.items()
    ]
