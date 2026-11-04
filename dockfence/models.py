"""Rule model + validation shared by the API, the store and the nft renderer."""

from __future__ import annotations

import ipaddress
import re
import time
from dataclasses import dataclass, field

DIRECTIONS = ("in", "out")
PROTOS = ("tcp", "udp", "icmp", "any")
ACTIONS = ("accept", "drop")

POLICY_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")


class ValidationError(ValueError):
    pass


@dataclass
class Rule:
    id: int | None = None
    policy_id: int = 0
    direction: str = "out"
    proto: str = "any"
    port: int | None = None
    port_end: int | None = None
    cidr: str = ""
    # DNS-based remote match (mutually exclusive with cidr): the rule matches
    # every IP that DNS answer capture has observed for this hostname.
    # Expanded into a per-rule nftables set — see nft.render_table.
    dns: str = ""
    action: str = "drop"
    enabled: bool = True
    position: int = 0
    comment: str = ""
    # log-and-continue before applying the verdict (anti-exfiltration
    # visibility for silent drop presets — same rate-limited NFLOG pattern
    # as the terminal pair)
    log: bool = False
    created: str = field(default_factory=lambda: time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()))

    def to_json(self) -> dict:
        return {
            "id": self.id,
            "policy_id": self.policy_id,
            "direction": self.direction,
            "proto": self.proto,
            "port": self.port,
            "port_end": self.port_end,
            "cidr": self.cidr,
            "dns": self.dns,
            "action": self.action,
            "enabled": self.enabled,
            "position": self.position,
            "comment": self.comment,
            "log": self.log,
            "created": self.created,
        }


def cidr_family(cidr: str) -> int | None:
    """Return 4/6 for a valid CIDR (or None for 'any'), raising on garbage."""
    cidr = (cidr or "").strip()
    if not cidr or cidr in ("0.0.0.0/0", "::/0"):
        return None
    try:
        net = ipaddress.ip_network(cidr, strict=False)
    except ValueError as exc:
        raise ValidationError(f"invalid cidr {cidr!r}: {exc}") from exc
    return net.version


DNS_NAME_RE = re.compile(
    r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$"
)


def normalize_dns_name(name: str) -> str:
    """Normalize + validate a rule's DNS name (FQDN, ≥2 labels, ≤253 chars).

    Exact names only — no wildcards. CNAME chains are followed by the DNS
    capture, so alias names are learned too and rules on any of them match."""
    name = (name or "").strip().lower()
    while name.endswith("."):
        name = name[:-1]
    if not name:
        return ""
    if len(name) > 253 or not DNS_NAME_RE.match(name):
        raise ValidationError(
            f"invalid dns name {name!r}: expected an FQDN like 'example.com'"
        )
    return name


def validate_rule(payload: dict, partial: bool = False) -> dict:
    """Validate a rule payload (full or partial PATCH). Returns normalized fields."""
    out: dict = {}

    if "direction" in payload or not partial:
        d = str(payload.get("direction", "out")).lower()
        if d not in DIRECTIONS:
            raise ValidationError(f"direction must be one of {DIRECTIONS}")
        out["direction"] = d

    if "proto" in payload or not partial:
        p = str(payload.get("proto", "any")).lower()
        if p not in PROTOS:
            raise ValidationError(f"proto must be one of {PROTOS}")
        out["proto"] = p

    if "action" in payload or not partial:
        a = str(payload.get("action", "accept")).lower()
        if a not in ACTIONS:
            raise ValidationError(f"action must be one of {ACTIONS}")
        out["action"] = a

    for key in ("port", "port_end"):
        if key in payload:
            val = payload[key]
            if val in (None, ""):
                out[key] = None
                continue
            try:
                val = int(val)
            except (TypeError, ValueError):
                raise ValidationError(f"{key} must be an integer") from None
            if not 1 <= val <= 65535:
                raise ValidationError(f"{key} must be 1..65535")
            out[key] = val
        elif not partial:
            out[key] = None

    if "cidr" in payload or not partial:
        cidr = str(payload.get("cidr") or "").strip()
        if cidr == "":
            out["cidr"] = ""
            out["cidr_family"] = None
        else:
            fam = cidr_family(cidr)
            out["cidr"] = str(ipaddress.ip_network(cidr, strict=False))
            out["cidr_family"] = fam

    if "dns" in payload or not partial:
        out["dns"] = normalize_dns_name(payload.get("dns"))

    if "enabled" in payload:
        out["enabled"] = bool(payload.get("enabled"))
    elif not partial:
        out["enabled"] = True

    if "comment" in payload or not partial:
        out["comment"] = str(payload.get("comment") or "").strip()[:200]

    if "log" in payload:
        out["log"] = bool(payload.get("log"))
    elif not partial:
        out["log"] = False

    if "position" in payload:
        try:
            out["position"] = int(payload.get("position"))
        except (TypeError, ValueError):
            raise ValidationError("position must be an integer") from None

    # Cross-field checks (only possible when the relevant fields are present)
    # remote side is matched by cidr OR dns name, never both (the API always
    # validates the merged rule, so both keys are present here)
    dns_val = str(out.get("dns") if "dns" in out else payload.get("dns") or "")
    cidr_val = str(out.get("cidr") if "cidr" in out else payload.get("cidr") or "")
    if dns_val and cidr_val:
        raise ValidationError(
            "a rule matches the remote side by cidr OR dns name, not both"
        )
    proto = out.get("proto")
    port = out.get("port") if "port" in out else None
    if not partial and proto in ("tcp", "udp"):
        if port is None:
            raise ValidationError(f"proto {proto!r} requires a destination port")
    if port is not None and proto == "icmp":
        raise ValidationError("proto 'icmp' must not carry a destination port")
    # proto 'any' WITH a dport is allowed: the renderer matches both tcp and udp
    # ('meta l4proto { tcp, udp } th dport N'), so 'allow DNS out' can be
    # expressed as one rule without picking a protocol.
    port_end = out.get("port_end")
    if port_end is not None and port is None:
        raise ValidationError("port_end requires a destination port")
    if port_end is not None and port is not None and port_end < port:
        raise ValidationError("port_end must be >= port")
    return out


def normalize_policy_name(name: str) -> str:
    name = (name or "").strip()
    if not POLICY_NAME_RE.match(name):
        raise ValidationError(
            f"invalid policy name {name!r}: must match {POLICY_NAME_RE.pattern}"
        )
    return name
