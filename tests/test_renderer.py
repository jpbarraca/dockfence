"""Renderer golden tests + nft --check validation."""

import json
import shutil
import subprocess

import pytest

from dockfence.config import Config
from dockfence.models import Rule
from dockfence.nft import TaggedContainer, render_table

GOLDEN = "tests/golden"


def sample_config(**kw) -> Config:
    cfg = Config(token="x", **kw)
    return cfg


def sample_rules() -> dict[str, list[Rule]]:
    return {
        "web": [
            Rule(id=7, policy_id=1, direction="out", proto="tcp", port=443,
                 cidr="203.0.113.4/32", action="accept", enabled=True, position=1),
            Rule(id=2, policy_id=1, direction="in", proto="tcp", port=8080,
                 cidr="10.0.0.0/8", action="accept", enabled=True, position=2),
            Rule(id=3, policy_id=1, direction="out", proto="udp", port=53,
                 action="accept", enabled=True, position=3),
            Rule(id=4, policy_id=1, direction="in", proto="tcp", port=80,
                 port_end=8080, action="accept", enabled=False, position=4,
                 comment="disabled rule"),
        ]
    }


def sample_containers() -> list[TaggedContainer]:
    return [
        TaggedContainer(
            id="abcdef123456fedcba98", short_id="abcdef123456", name="web",
            policy="web", ips4=["172.18.0.5"], ips6=["fd12:3456:7890:1::5"],
        ),
        TaggedContainer(
            id="111122223333444455556666", short_id="111122223333", name="db",
            policy="web", ips4=["172.18.0.6"], ips6=[],
        ),
    ]


def test_enforcing_matches_golden():
    cfg = sample_config(ipv6=True)
    out = render_table(cfg, sample_containers(), sample_rules(), "enforcing")
    golden = open(f"{GOLDEN}/enforcing.nft").read()
    assert out == golden


def test_monitor_matches_golden():
    cfg = sample_config(ipv6=True)
    out = render_table(cfg, sample_containers(), sample_rules(), "monitor")
    golden = open(f"{GOLDEN}/monitor.nft").read()
    assert out == golden


def test_no_ipv6_without_flag():
    cfg = sample_config(ipv6=False)
    out = render_table(cfg, sample_containers(), sample_rules(), "enforcing")
    assert "ip6" not in out


def test_no_host_filter():
    cfg = sample_config(ipv6=False, filter_host=False)
    out = render_table(cfg, sample_containers(), sample_rules(), "enforcing")
    assert "chain dfw_inp" not in out


def test_terminal_pair_is_never_limit_drop():
    """'limit' is a match: log-rule and drop-rule must be separate."""
    cfg = sample_config(ipv6=False)
    out = render_table(cfg, sample_containers(), sample_rules(), "enforcing")
    assert "limit drop" not in out
    assert 'prefix "DFW;c=abcdef123456;d=web;dir=out;" counter' in out
    assert "counter drop" in out


def test_disabled_mode_renders_empty_table():
    cfg = sample_config(ipv6=True)
    out = render_table(cfg, sample_containers(), sample_rules(), "disabled")
    assert "jump" not in out and "log group" not in out


def test_deterministic():
    cfg = sample_config(ipv6=True)
    a = render_table(cfg, list(reversed(sample_containers())), sample_rules(), "enforcing")
    b = render_table(cfg, sample_containers(), sample_rules(), "enforcing")
    assert a == b


def test_rule_comments_present():
    cfg = sample_config(ipv6=False)
    out = render_table(cfg, sample_containers(), sample_rules(), "enforcing")
    assert 'comment "r#7"' in out
    assert 'comment "r#4|disabled rule"' not in out  # disabled rule not rendered


def test_any_proto_with_port_renders_tcp_and_udp_match():
    """'any' + dport → single rule matching both tcp and udp (th dport)."""
    rules = {
        "web": [
            Rule(id=1, policy_id=1, direction="out", proto="any", port=53,
                 action="accept", position=1),
            Rule(id=2, policy_id=1, direction="out", proto="any", port=1000,
                 port_end=2000, action="drop", position=2),
        ]
    }
    out = render_table(sample_config(ipv6=False), sample_containers(), rules, "enforcing")
    assert "meta l4proto { tcp, udp } th dport 53 counter accept" in out
    assert "meta l4proto { tcp, udp } th dport 1000-2000 counter drop" in out


def test_nft_check_validates_any_port_syntax():
    if not shutil.which("nft"):
        pytest.skip("nft not installed")
    rules = {
        "web": [
            Rule(id=1, policy_id=1, direction="out", proto="any", port=53,
                 action="accept", position=1),
        ]
    }
    out = render_table(sample_config(ipv6=False), sample_containers(), rules, "enforcing")
    proc = subprocess.run(["nft", "--check", "-f", "-"], input=out,
                          capture_output=True, text=True, timeout=30)
    if "Operation not permitted" in proc.stderr or "netlink" in proc.stderr:
        pytest.skip("no CAP_NET_ADMIN in this environment")
    assert proc.returncode == 0, proc.stderr


def test_log_rule_emits_log_and_continue():
    """Anti-exfiltration deny rules log (rate-limited) before the silent drop."""
    rules = {
        "web": [
            Rule(id=9, policy_id=1, direction="out", proto="tcp", port=445,
                 cidr="10.0.0.0/8", action="drop", log=True, position=1,
                 comment="deny private"),
        ]
    }
    cfg = sample_config(ipv6=False)
    out = render_table(cfg, sample_containers(), rules, "enforcing")
    chain = out.split("chain c_abcdef123456_out")[1].split("\n  }")[0]
    lines = [l.strip() for l in chain.splitlines() if l.strip()]
    log_line = next((l for l in lines if "log group 5" in l and "dport 445" in l), None)
    drop_line = next((l for l in lines if "dport 445" in l and "counter drop" in l), None)
    assert log_line and drop_line
    assert lines.index(log_line) < lines.index(drop_line)
    # log-and-continue: rate-limited log statement, no verdict of its own
    assert " drop" not in log_line and " accept" not in log_line
    # verdict rule itself is silent (no log statement)
    assert "log group" not in drop_line


def test_log_rule_not_duplicated_in_monitor():
    """Monitor already logs everything at the terminal pair — no extra log line."""
    rules = {
        "web": [
            Rule(id=9, policy_id=1, direction="out", proto="tcp", port=445,
                 cidr="10.0.0.0/8", action="drop", log=True, position=1),
        ]
    }
    cfg = sample_config(ipv6=False)
    out = render_table(cfg, sample_containers(), rules, "monitor")
    chain = out.split("chain c_abcdef123456_out")[1].split("\n  }")[0]
    assert not [l for l in chain.splitlines() if "dport 445" in l and "log group" in l]


def test_nft_check_validates_log_rule_syntax():
    """Dry-run the log-and-continue pattern through the real nft binary."""
    if not shutil.which("nft"):
        pytest.skip("nft not installed")
    rules = {
        "web": [
            Rule(id=9, policy_id=1, direction="out", proto="any",
                 cidr="10.0.0.0/8", action="drop", log=True, position=1),
        ]
    }
    cfg = sample_config(ipv6=False)
    out = render_table(cfg, sample_containers(), rules, "enforcing")
    proc = subprocess.run(["nft", "--check", "-f", "-"], input=out,
                          capture_output=True, text=True, timeout=30)
    if "Operation not permitted" in proc.stderr or "netlink" in proc.stderr:
        pytest.skip("no CAP_NET_ADMIN in this environment")
    assert proc.returncode == 0, proc.stderr


def test_nft_check_validates_rendered_table():
    """Dry-run the rendered table through the real nft binary when available."""
    if not shutil.which("nft"):
        pytest.skip("nft not installed")
    cfg = sample_config(ipv6=True)
    out = render_table(cfg, sample_containers(), sample_rules(), "enforcing")
    proc = subprocess.run(["nft", "--check", "-f", "-"], input=out,
                          capture_output=True, text=True, timeout=30)
    if "Operation not permitted" in proc.stderr or "netlink" in proc.stderr:
        pytest.skip("no CAP_NET_ADMIN in this environment")
    assert proc.returncode == 0, proc.stderr


def test_logging_off_renders_no_nflog():
    """'log: off' (the default) suppresses every NFLOG rule; enforcement stays."""
    cfg = sample_config(ipv6=False)
    out = render_table(cfg, sample_containers(), sample_rules(), "enforcing", logging=False)
    assert "log group" not in out
    assert "counter drop" in out  # terminal verdicts unchanged
    assert "ip daddr 203.0.113.4/32 tcp dport 443 counter accept comment \"r#7\"" in out
    # monitor mode + logging off = silent accept (visibility requires logging)
    out = render_table(cfg, sample_containers(), sample_rules(), "monitor", logging=False)
    assert "log group" not in out and "counter accept" in out


def test_dns_capture_chains_render_and_gate():
    """DNS capture is containers-only: fwd is daddr-restricted, out covers the
    embedded resolver, and there is no input hook (host lookups stay silent)."""
    cfg = sample_config(ipv6=False)
    out = render_table(cfg, sample_containers(), sample_rules(), "enforcing", dns_log=True)
    # forward hook: answers delivered TO container IPs (Docker DNAT preserves src)
    assert "chain dfw_dns_fwd" in out
    assert 'ip daddr { 172.18.0.5, 172.18.0.6 } udp sport 53 log group 6 prefix "DFW;dns;"' in out
    assert 'ip daddr { 172.18.0.5, 172.18.0.6 } tcp sport 53 log group 6 prefix "DFW;dns;"' in out
    # output hook: embedded resolver 127.0.0.11 replies (defensive) + same daddr rules
    assert "chain dfw_dns_out" in out
    assert 'ip saddr 127.0.0.11 udp sport 53 log group 6 prefix "DFW;dns;"' in out
    assert 'ip saddr 127.0.0.11 tcp sport 53 log group 6 prefix "DFW;dns;"' in out
    assert 'ip daddr { 172.18.0.5, 172.18.0.6 } udp sport 53 log group 6 prefix "DFW;dns;"' in out
    # the input hook that captured the HOST's own lookups is gone
    assert "dfw_dns_inp" not in out
    assert "priority filter + 11; policy accept" in out
    # default: no dns chains at all
    assert "dfw_dns" not in render_table(cfg, sample_containers(), sample_rules(), "enforcing")
    # no tagged containers → nothing to attribute DNS to → no capture chains
    assert "dfw_dns" not in render_table(cfg, [], {}, "enforcing", dns_log=True)


def test_nft_check_validates_dns_capture_and_silent_chains():
    """Dry-run the dns capture + log-off rendering through the real nft binary."""
    if not shutil.which("nft"):
        pytest.skip("nft not installed")
    cfg = sample_config(ipv6=True)
    out = render_table(cfg, sample_containers(), sample_rules(), "enforcing",
                       logging=False, dns_log=True)
    proc = subprocess.run(["nft", "--check", "-f", "-"], input=out,
                          capture_output=True, text=True, timeout=30)
    if "Operation not permitted" in proc.stderr or "netlink" in proc.stderr:
        pytest.skip("no CAP_NET_ADMIN in this environment")
    assert proc.returncode == 0, proc.stderr


def test_rule_counters_parse(monkeypatch):
    """nft -j counters map to rule ids via the 'r#<id>' verdict comment.
    Counters are in-kernel memory increments — nothing is logged."""
    from dockfence.nft import NftApplier, NftError
    applier = NftApplier(sample_config(ipv6=False))
    # nft ≥1.0 shape: rules are top-level entries, verdicts like {"accept": null}
    sample = json.dumps({"nftables": [
        {"metainfo": {"version": "1.1.6"}},
        {"chain": {"name": "dfw_fwd", "handle": 1}},
        {"rule": {"family": "inet", "table": "dockfence",
                  "chain": "c_abcdef123456_out", "handle": 7, "expr": [
                      {"counter": {"packets": 12, "bytes": 3456}},
                      {"accept": None},
                      {"comment": {"comment": "r#7"}}]}},
        # terminal pair: counter but no r# comment → skipped
        {"rule": {"family": "inet", "table": "dockfence",
                  "chain": "c_abcdef123456_out", "handle": 8, "expr": [
                      {"counter": {"packets": 1, "bytes": 60}},
                      {"drop": None}]}},
        # user comment is glued after the id with '|'
        {"rule": {"family": "inet", "table": "dockfence",
                  "chain": "c_abcdef123456_out", "handle": 9, "expr": [
                      {"counter": {"packets": 3, "bytes": 180}},
                      {"comment": {"comment": "r#22|dup-test"}}]}},
        # dns capture rule: counter, no r# → skipped
        {"rule": {"family": "inet", "table": "dockfence",
                  "chain": "dfw_dns_fwd", "handle": 10, "expr": [
                      {"counter": {"packets": 9, "bytes": 720}}]}},
        # older shape: rules nested inside the chain object still parse
        {"chain": {"name": "c_111122223333_in", "rules": [
            {"expr": [{"counter": {"packets": 5, "bytes": 100}},
                      {"comment": {"comment": "r#9"}}]}]}},
    ]})
    monkeypatch.setattr(applier, "_run", lambda args, stdin=None: sample)
    assert applier.rule_counters() == {7: {"packets": 12, "bytes": 3456},
                                       22: {"packets": 3, "bytes": 180},
                                       9: {"packets": 5, "bytes": 100}}

    def boom(args, stdin=None):
        raise NftError("nft failed")

    monkeypatch.setattr(applier, "_run", boom)
    assert applier.rule_counters() == {}  # best-effort


def test_rule_counters_rule_level_comment(monkeypatch):
    """nft 1.1.6 emits the comment at rule level, not as an expr."""
    from dockfence.nft import NftApplier
    applier = NftApplier(sample_config(ipv6=False))
    sample = json.dumps({"nftables": [
        {"rule": {"family": "inet", "table": "dockfence",
                  "chain": "c_abcdef123456_in", "handle": 11, "comment": "r#4",
                  "expr": [{"counter": {"packets": 0, "bytes": 0}}]}},
    ]})
    monkeypatch.setattr(applier, "_run", lambda args, stdin=None: sample)
    assert applier.rule_counters() == {4: {"packets": 0, "bytes": 0}}


def test_counters_per_chain(monkeypatch):
    """counters() sums every counter expr per chain (top-level rule shape)."""
    from dockfence.nft import NftApplier
    applier = NftApplier(sample_config(ipv6=False))
    sample = json.dumps({"nftables": [
        {"rule": {"chain": "c_abcdef123456_out", "expr": [
            {"counter": {"packets": 10, "bytes": 1000}}]}},
        {"rule": {"chain": "c_abcdef123456_out", "expr": [
            {"counter": {"packets": 2, "bytes": 120}}]}},
        {"rule": {"chain": "c_abcdef123456_in", "expr": [
            {"counter": {"packets": 7, "bytes": 700}}]}},
    ]})
    monkeypatch.setattr(applier, "_run", lambda args, stdin=None: sample)
    assert applier.counters() == {
        "c_abcdef123456_out": {"packets": 12, "bytes": 1120},
        "c_abcdef123456_in": {"packets": 7, "bytes": 700},
    }


def test_dns_rule_expands_to_set():
    cfg = sample_config(ipv6=True)
    rules = {"web": [Rule(id=12, policy_id=1, direction="out", proto="tcp", port=443,
                          dns="example.com", action="accept", enabled=True, position=1)]}
    dns_sets = {"example.com": {"4": ["203.0.113.4", "198.51.100.8"], "6": ["2001:db8::1"]}}
    out = render_table(cfg, sample_containers(), rules, "enforcing", dns_log=False,
                       dns_sets=dns_sets)
    assert "set dns12 {\n    type ipv4_addr\n    elements = { 198.51.100.8, 203.0.113.4 }\n  }" in out
    assert "set dns126 {\n    type ipv6_addr\n    elements = { 2001:db8::1 }\n  }" in out
    # one match line per family inside the out chain
    assert "ip daddr @dns12 tcp dport 443 counter accept comment \"r#12\"" in out
    assert "ip6 daddr @dns126 tcp dport 443 counter accept comment \"r#12\"" in out


def test_dns_rule_empty_set_fails_closed():
    cfg = sample_config()
    rules = {"web": [Rule(id=5, policy_id=1, direction="in", proto="any", dns="nowhere.example",
                          action="accept", enabled=True, position=1)]}
    out = render_table(cfg, sample_containers(), rules, "enforcing", dns_sets={})
    assert "set dns5 {\n    type ipv4_addr\n  }" in out          # defined, empty
    assert "elements" not in out                                  # no elements rendered
    # in-direction matches the SOURCE side; proto any + no port → no l4 match
    assert "ip saddr @dns5 counter accept comment \"r#5\"" in out
    assert "dns126" not in out                                    # ipv6 disabled


def test_dns_rule_disabled_not_rendered():
    cfg = sample_config()
    rules = {"web": [Rule(id=6, policy_id=1, direction="out", proto="tcp", port=443,
                          dns="example.com", action="accept", enabled=False, position=1)]}
    out = render_table(cfg, sample_containers(), rules, "enforcing", dns_sets={"example.com": {"4": ["1.2.3.4"]}})
    assert "set dns6" not in out and "@dns6" not in out
