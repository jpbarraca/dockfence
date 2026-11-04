"""nftables compiler/applier.

Renders the complete desired `table inet dockfence` and applies it as ONE
atomic `nft -f` batch (the whole file is a single netlink transaction:
on any error nothing is applied). The kernel is a pure projection of the
store; a failed apply simply keeps the last good kernel state.
"""

from __future__ import annotations

import json
import re
import subprocess
from dataclasses import dataclass, field

from .config import Config
from .dnslog import DNS_LOG_PREFIX
from .models import Rule

# terminal log/drop rules per container chain (rate-limited NFLOG, then drop)
FWD_CT = "ct state established,related counter accept"


class NftError(Exception):
    pass


@dataclass
class TaggedContainer:
    """A container that opted in via label and is filterable."""

    id: str
    short_id: str
    name: str
    policy: str
    ips4: list[str] = field(default_factory=list)
    ips6: list[str] = field(default_factory=list)


def _dport_match(port: int | None, port_end: int | None, prefix: str) -> str:
    if port_end and port_end != port:
        return f"{prefix} dport {port}-{port_end}"
    return f"{prefix} dport {port}"


def _l4_match(rule: Rule) -> str:
    """Layer-4 match fragment for a rule (destination port of the flow)."""
    if rule.proto in ("tcp", "udp"):
        return _dport_match(rule.port, rule.port_end, rule.proto)
    if rule.proto == "icmp":
        # inet table: covers ICMPv4 and, when IPv6 is enabled, ICMPv6
        return "meta l4proto { icmp, ipv6-icmp }"
    if rule.port is not None:
        # proto 'any' with a dport: matches BOTH tcp and udp (nft transport
        # header is protocol-agnostic once l4proto is constrained)
        return _dport_match(rule.port, rule.port_end, "meta l4proto { tcp, udp } th")
    return ""


def _remote_match(rule: Rule, direction: str) -> str:
    """Match fragment for the remote side: src for ingress, dst for egress."""
    if not rule.cidr:
        return ""
    key = "saddr" if direction == "in" else "daddr"
    fam = "ip6" if ":" in rule.cidr else "ip"
    return f"{fam} {key} {rule.cidr}"


def _dns_set_name(rule: Rule, fam: str) -> str:
    """Kernel set name for a dns-rule's observed answer IPs (v4 = dns<id>)."""
    return f"dns{rule.id}" + ("" if fam == "4" else "6")


def _remote_matches(rule: Rule, direction: str, ipv6: bool = False) -> list[str]:
    """Remote-side match fragments, ONE PER ADDRESS FAMILY (one rule line each).

    dns rules match a named set per family (rendered from the DNS answer
    capture; empty set = matches nothing = fail-closed until the name has
    been observed). cidr rules keep the single static fragment."""
    key = "saddr" if direction == "in" else "daddr"
    if rule.dns:
        out = [f"ip {key} @{_dns_set_name(rule, '4')}"]
        if ipv6:
            out.append(f"ip6 {key} @{_dns_set_name(rule, '6')}")
        return out
    return [_remote_match(rule, direction)] if rule.cidr else []


def _matches(rule: Rule) -> str:
    """Match fragment (remote side + layer-4) without the verdict (v4 view)."""
    return " ".join(p for p in (_remote_match(rule, rule.direction), _l4_match(rule)) if p)


def _matches_all(rule: Rule, ipv6: bool = False) -> list[str]:
    """Match fragments per family, each with the layer-4 match appended."""
    remotes = _remote_matches(rule, rule.direction, ipv6)
    l4 = _l4_match(rule)
    if not remotes:
        return [l4] if l4 else [""]
    return [f"{r} {l4}".strip() if l4 else r for r in remotes]


def _comment(rule: Rule) -> str:
    comment = f"r#{rule.id}" if rule.id is not None else ""
    if rule.comment:
        comment = f"{comment}|{rule.comment}" if comment else rule.comment
    return comment


def _verdict_line(match: str, rule: Rule, mode: str = "enforcing") -> str:
    # monitor mode = full visibility, zero enforcement: drop rules accept too
    action = rule.action if mode == "enforcing" else "accept"
    line = " ".join([*match.split(), "counter", action]) if match \
        else f"counter {action}"
    comment = _comment(rule)
    if comment:
        line += f' comment "{comment}"'
    return line


def rule_verdict(rule: Rule, mode: str = "enforcing") -> str:
    return _verdict_line(_matches(rule), rule, mode)


def _rule_lines(rule: Rule, mode: str = "enforcing", ipv6: bool = False) -> list[str]:
    """Verdict lines for a rule — one per address family (dns rules expand)."""
    return [_verdict_line(m, rule, mode) for m in _matches_all(rule, ipv6)]


def _container_chains(
    c: TaggedContainer, rules: list[Rule], cfg: Config, mode: str, logging: bool = True
) -> str:
    out = []
    # nft ≥ 0.9: nfnetlink logging is the 'log group' statement (nflog form)
    # logging=False (the default setting) renders NO log rules at all: the
    # terminal pair is a plain counter+verdict and per-rule log lines vanish.
    terminal = (
        f'limit rate {cfg.log_rate}/{cfg.log_rate_unit} burst {cfg.log_burst} packets '
        f'log group {cfg.log_group} '
        f'prefix "DFW;c={c.short_id};d={c.policy};dir=%DIR%;" counter'
    )
    for direction in ("out", "in"):
        body = [f"  chain c_{c.short_id}_{direction} {{", f"    # {c.policy}: {direction} ({c.name})"]
        for r in rules:
            if not r.enabled or r.direction != direction:
                continue
            frags = _matches_all(r, cfg.ipv6)
            if r.log and mode == "enforcing" and logging:
                # log-and-continue BEFORE a silent drop (anti-exfiltration
                # deny presets): same rate-limited NFLOG pattern as the
                # terminal pair, so blocked attempts stay visible — one log
                # line per address family (dns rules match a set per family)
                for frag in frags:
                    body.append("    " + (frag + " " if frag else "")
                                + terminal.replace("%DIR%", direction))
            body.extend(f"    {line}" for line in _rule_lines(r, mode, cfg.ipv6))
        # terminal pair: log (while under rate) then drop/accept.
        # 'limit' is a MATCH — a single 'limit ... drop' would let burst
        # traffic through once over rate. Rule 1 logs only under rate,
        # rule 2 handles everything else.
        if logging:
            body.append("    " + terminal.replace("%DIR%", direction))
        if mode == "monitor" or mode == "disabled":
            body.append("    counter accept")
        else:
            body.append("    counter drop")
        body.append("  }")
        out.append("\n".join(body))
    return "\n\n".join(out)


def _dns_chains(cfg: Config, tagged: list[TaggedContainer]) -> list[str]:
    """Passive DNS answer capture — containers only (settings toggle 'dns').

    Docker DNATs a container's queries to its embedded resolver (127.0.0.11)
    straight to the upstream resolver while preserving the container source
    address, so answers to containers cross the FORWARD hook addressed to the
    container. Captured are:
      - answers delivered to tagged container IPs (forward + output hooks),
      - replies from Docker's embedded resolver itself (output hook, src
        127.0.0.11 — only Docker's DNS proxy uses that address).
    The host's own DNS (input hook) is deliberately NOT captured.
    Non-terminating rules in accept-policy chains — purely observational."""
    g = cfg.dns_group
    ips4 = sorted({ip for c in tagged for ip in c.ips4})
    ips6 = sorted({ip for c in tagged for ip in c.ips6}) if cfg.ipv6 else []
    if not ips4 and not ips6:
        return []  # nothing to attribute DNS to — no capture at all
    dst4 = "{ " + ", ".join(ips4) + " }" if ips4 else None
    dst6 = "{ " + ", ".join(ips6) + " }" if ips6 else None

    def answer_rules(dst: str, fam: str) -> list[str]:
        return [
            f'    {fam} daddr {dst} udp sport 53 log group {g} prefix "{DNS_LOG_PREFIX}"',
            f'    {fam} daddr {dst} tcp sport 53 log group {g} prefix "{DNS_LOG_PREFIX}"',
        ]

    fwd = ["  chain dfw_dns_fwd {",
           "    type filter hook forward priority filter + 11; policy accept;"]
    if dst4:
        fwd += answer_rules(dst4, "ip")
    if dst6:
        fwd += answer_rules(dst6, "ip6")
    fwd.append("  }")

    out = ["  chain dfw_dns_out {",
           "    type filter hook output priority filter + 11; policy accept;"]
    if dst4:
        out += [
            f'    ip saddr 127.0.0.11 udp sport 53 log group {g} prefix "{DNS_LOG_PREFIX}"',
            f'    ip saddr 127.0.0.11 tcp sport 53 log group {g} prefix "{DNS_LOG_PREFIX}"',
        ]
        out += answer_rules(dst4, "ip")
    if dst6:
        out += answer_rules(dst6, "ip6")
    out.append("  }")
    return [*fwd, *out]


def _dns_sets(cfg: Config, rules_by_policy: dict[str, list[Rule]],
              dns_sets: dict[str, dict[str, list[str]]] | None) -> list[str]:
    """Named sets, one per enabled dns-rule, holding the answer IPs observed
    by the DNS capture. Defined even when EMPTY: an empty set matches nothing,
    so an allow dns-rule stays fail-closed until the name has been seen."""
    if dns_sets is None:
        return []
    out: list[str] = []
    seen: set[int] = set()
    for rules in rules_by_policy.values():
        for r in rules:
            if not r.enabled or not r.dns or r.id is None or r.id in seen:
                continue
            seen.add(r.id)
            fams = dns_sets.get(r.dns, {})
            els4 = sorted(set(fams.get("4", [])))
            els6 = sorted(set(fams.get("6", [])))
            block = f"  set dns{r.id} {{\n    type ipv4_addr\n"
            if els4:
                block += f"    elements = {{ {', '.join(els4)} }}\n"
            out.append(block + "  }")
            if cfg.ipv6:
                block6 = f"  set dns{r.id}6 {{\n    type ipv6_addr\n"
                if els6:
                    block6 += f"    elements = {{ {', '.join(els6)} }}\n"
                out.append(block6 + "  }")
    return out


def render_table(
    cfg: Config,
    tagged: list[TaggedContainer],
    rules_by_policy: dict[str, list[Rule]],
    mode: str,
    logging: bool = True,
    dns_log: bool = False,
    dns_sets: dict[str, dict[str, list[str]]] | None = None,
) -> str:
    """Render the complete desired table. Deterministic output (sorted).
    logging=False suppresses every NFLOG rule (settings default); dns_log=True
    adds the passive DNS answer capture chains."""
    tagged = sorted(tagged, key=lambda c: (c.name, c.short_id))
    chains: list[str] = []

    fwd_jumps: list[str] = []
    inp_jumps: list[str] = []

    for c in tagged:
        rules = rules_by_policy.get(c.policy, [])
        chains.append(_container_chains(c, rules, cfg, mode, logging))
        for ip in sorted(c.ips4):
            fwd_jumps.append(
                f'    ip saddr {ip} jump c_{c.short_id}_out comment "out {c.policy}"'
            )
            fwd_jumps.append(
                f'    ip daddr {ip} jump c_{c.short_id}_in comment "in {c.policy}"'
            )
            if cfg.filter_host:
                inp_jumps.append(
                    f'    ip saddr {ip} jump c_{c.short_id}_out comment "host-access {c.policy}"'
                )
        if cfg.ipv6:
            for ip in sorted(c.ips6):
                fwd_jumps.append(
                    f'    ip6 saddr {ip} jump c_{c.short_id}_out comment "out6 {c.policy}"'
                )
                fwd_jumps.append(
                    f'    ip6 daddr {ip} jump c_{c.short_id}_in comment "in6 {c.policy}"'
                )
                if cfg.filter_host:
                    inp_jumps.append(
                        f'    ip6 saddr {ip} jump c_{c.short_id}_out comment "host-access6 {c.policy}"'
                    )

    lines = [
        "#!/usr/sbin/nft -f",
        "# dockfence generated ruleset — DO NOT EDIT BY HAND.",
        "# Rendered by dockfence; applied as one atomic transaction.",
        f"table inet {cfg.table} {{",
    ]
    if mode == "disabled":
        # no enforcement at all: empty table body (applier removes the table)
        lines.append("}")
        return "\n".join(lines) + "\n"
    lines += _dns_sets(cfg, rules_by_policy, dns_sets)
    lines += [
        "  chain dfw_fwd {",
        "    type filter hook forward priority filter + 10; policy accept;",
        f"    {FWD_CT}",
        *fwd_jumps,
        "  }",
    ]
    if cfg.filter_host:
        lines += [
            "  chain dfw_inp {",
            "    type filter hook input priority filter + 10; policy accept;",
            *inp_jumps,
            "  }",
        ]
    if dns_log:
        lines += _dns_chains(cfg, tagged)
    lines += chains
    lines.append("}")
    return "\n".join(lines) + "\n"


class NftApplier:
    def __init__(self, cfg: Config):
        self.cfg = cfg
        self._use_destroy = True  # nft >= 1.0.6; falls back to delete otherwise

    # -- low-level helpers --------------------------------------------------
    def _run(self, args: list[str], stdin: str | None = None) -> str:
        try:
            proc = subprocess.run(
                [self.cfg.nft_binary, *args],
                input=stdin,
                capture_output=True,
                text=True,
                timeout=30,
            )
        except FileNotFoundError:
            raise NftError(f"nft binary not found: {self.cfg.nft_binary}") from None
        if proc.returncode != 0:
            raise NftError(f"nft {' '.join(args)} failed: {proc.stderr.strip()}")
        return proc.stdout

    def list_tables(self) -> list[dict]:
        out = self._run(["-j", "list", "tables"])
        try:
            return json.loads(out).get("nftables", [])
        except json.JSONDecodeError:
            return []

    def table_exists(self) -> bool:
        for entry in self.list_tables():
            obj = entry.get("table")
            if obj and obj.get("name") == self.cfg.table and obj.get("family") == "inet":
                return True
        return False

    def _destroy_prefix(self) -> str:
        if self._use_destroy:
            return f"destroy table inet {self.cfg.table}\n"
        if self.table_exists():
            return f"delete table inet {self.cfg.table}\n"
        return ""

    # -- main entry points --------------------------------------------------
    def apply(self, rendered: str) -> None:
        """Apply the rendered table atomically. Raises NftError on failure,
        in which case the kernel keeps the last good table."""
        text = self._destroy_prefix() + rendered
        try:
            self._run(["-f", "-"], stdin=text)
        except NftError as exc:
            if self._use_destroy and ("destroy" in str(exc) or "syntax" in str(exc).lower()):
                # older nft without 'destroy' — retry with delete-based path
                self._use_destroy = False
                text = self._destroy_prefix() + rendered
                self._run(["-f", "-"], stdin=text)
                return
            raise

    def delete_table(self) -> None:
        """Remove our table entirely (used by FW_MODE=disabled)."""
        if not self.table_exists():
            return
        try:
            self._run(["-f", "-"], stdin=f"destroy table inet {self.cfg.table}\n")
        except NftError:
            self._run(["delete", "table", "inet", self.cfg.table])

    def _table_rules(self) -> list[dict]:
        """All rule objects of the live table, flattened. nft ≥1.0 emits rules
        as top-level entries; other versions nest them in the chain object."""
        out = self._run(["-j", "list", "table", "inet", self.cfg.table])
        entries = json.loads(out).get("nftables", [])
        rules: list[dict] = []
        for entry in entries:
            if "rule" in entry:
                rules.append(entry["rule"])
            elif "chain" in entry:
                rules.extend(entry["chain"].get("rules") or [])
        return rules

    def counters(self) -> dict[str, dict]:
        """Per-chain counters from the live table: {chain: {packets, bytes}}.
        Best-effort: returns {} when the table does not exist or nft -j fails."""
        try:
            rules = self._table_rules()
        except (NftError, json.JSONDecodeError, KeyError, TypeError):
            return {}
        result: dict[str, dict] = {}
        for rule in rules:
            counters = result.setdefault(rule.get("chain") or "",
                                         {"packets": 0, "bytes": 0})
            for expr in rule.get("expr", []):
                if "counter" in expr:
                    counters["packets"] += int(expr["counter"].get("packets", 0))
                    counters["bytes"] += int(expr["counter"].get("bytes", 0))
        return result

    def rule_counters(self) -> dict[int, dict]:
        """Live per-rule packet/byte counters keyed by rule id (parsed from the
        'r#<id>' verdict comment). nftables counters are in-kernel memory
        increments read on demand — no logging, nothing touches syslog.
        Best-effort: returns {} when the table is missing or nft fails."""
        try:
            rules = self._table_rules()
        except (NftError, json.JSONDecodeError, KeyError, TypeError):
            return {}
        result: dict[int, dict] = {}
        for rule in rules:
            rid = None
            packets = total_bytes = 0
            has_counter = False
            for expr in rule.get("expr", []):
                if "counter" in expr:
                    has_counter = True
                    packets += int(expr["counter"].get("packets", 0))
                    total_bytes += int(expr["counter"].get("bytes", 0))
                elif "comment" in expr:
                    rid = _rule_id_from_comment(
                        str(expr["comment"].get("comment", ""))) or rid
            if rid is None:
                # nft 1.1.6 emits the comment at rule level, not as an expr
                rid = _rule_id_from_comment(str(rule.get("comment") or ""))
            if rid is not None and has_counter:
                result[rid] = {"packets": packets, "bytes": total_bytes}
        return result


def _rule_id_from_comment(comment: str) -> int | None:
    m = re.match(r"r#(\d+)", comment)
    return int(m.group(1)) if m else None
