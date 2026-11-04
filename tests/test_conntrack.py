"""Conntrack parsing + per-container session selection (active-sessions view)."""

import subprocess

import pytest

from dockfence import conntrack
from dockfence.conntrack import _parse_line, read_entries, sessions_for

V4_EST = ("ipv4 2 tcp 6 43199 ESTABLISHED "
          "src=172.18.0.5 dst=140.82.121.4 sport=41234 dport=443 "
          "src=140.82.121.4 dst=172.18.0.1 sport=443 dport=41234 "
          "[ASSURED] mark=0 use=1")

V4_DNAT_IN = ("ipv4 2 tcp 6 119 SYN_SENT "
              "src=203.0.113.9 dst=198.51.100.20 sport=5555 dport=8080 "
              "src=172.18.0.5 dst=203.0.113.9 sport=80 dport=5555")

V6_EST = ("ipv6 2 tcp 6 43199 ESTABLISHED "
          "src=fd00::5 dst=2001:db8::1 sport=41234 dport=443 "
          "src=2001:db8::1 dst=fd00::5 sport=443 dport=41234")

V4_UDP = ("ipv4 2 udp 29 "
          "src=172.18.0.5 dst=8.8.8.8 sport=5353 dport=53 "
          "src=8.8.8.8 dst=172.18.0.5 sport=53 dport=5353 [ASSURED]")


def test_parse_established_v4():
    e = _parse_line(V4_EST)
    assert e["family"] == "ipv4" and e["proto"] == "tcp"
    assert e["state"] == "ESTABLISHED" and e["timeout"] == 43199
    assert e["assured"] is True
    # original tuple = initiator, reply tuple = responder (split at 2nd src=)
    assert (e["src"], e["sport"], e["dst"], e["dport"]) == \
        ("172.18.0.5", 41234, "140.82.121.4", 443)
    assert (e["reply_src"], e["reply_sport"], e["reply_dst"], e["reply_dport"]) == \
        ("140.82.121.4", 443, "172.18.0.1", 41234)


def test_parse_udp_has_no_state():
    e = _parse_line(V4_UDP)
    assert e["proto"] == "udp" and e["state"] == ""
    assert e["timeout"] == 29 and e["assured"] is True


def test_parse_ipv6_family():
    e = _parse_line(V6_EST)
    assert e["family"] == "ipv6" and e["src"] == "fd00::5"
    assert e["reply_dst"] == "fd00::5"


def test_parse_garbage_lines():
    assert _parse_line("") is None
    assert _parse_line("garbage line without tuples") is None
    # no src= anywhere → nothing to attribute
    assert _parse_line("ipv4 2 tcp 6 43199 ESTABLISHED mark=0 use=1") is None


def test_single_tuple_entry_has_empty_reply():
    e = _parse_line("ipv4 2 tcp 6 10 SYN_SENT src=172.18.0.5 dst=10.0.0.1 sport=1 dport=2")
    assert e["reply_src"] == "" and e["reply_sport"] is None
    assert e["state"] == "SYN_SENT"


def test_sessions_out_direction():
    rows = sessions_for([_parse_line(V4_EST)], {"172.18.0.5"})
    assert len(rows) == 1
    r = rows[0]
    assert r["dir"] == "out" and r["dst"] == "140.82.121.4" and r["dport"] == 443
    assert r["sport"] == 41234 and r["assured"] is True


def test_sessions_in_direction_dnat_and_dst():
    # published-port DNAT: the container IP is the reply (SNAT'd) source
    rows = sessions_for([_parse_line(V4_DNAT_IN)], {"172.18.0.5"})
    assert rows[0]["dir"] == "in"
    assert rows[0]["src"] == "203.0.113.9" and rows[0]["dport"] == 8080
    # container IP as the original destination also counts as 'in'
    line = ("ipv4 2 tcp 6 43199 ESTABLISHED "
            "src=10.0.0.9 dst=172.18.0.5 sport=3333 dport=80 "
            "src=172.18.0.5 dst=10.0.0.9 sport=80 dport=3333")
    assert sessions_for([_parse_line(line)], {"172.18.0.5"})[0]["dir"] == "in"


def test_sessions_other_containers_skipped():
    assert sessions_for([_parse_line(V4_EST)], {"172.18.0.99"}) == []


def test_sessions_established_first_and_limit():
    entries = [_parse_line(V4_DNAT_IN), _parse_line(V4_EST), _parse_line(V6_EST)]
    rows = sessions_for(entries, {"172.18.0.5", "fd00::5"}, limit=2)
    assert [r["state"] for r in rows] == ["ESTABLISHED", "ESTABLISHED"]
    assert len(rows) == 2


class FakeProc:
    def __init__(self, returncode=0, stdout="", stderr=""):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


def test_read_entries_procfs(tmp_path):
    p = tmp_path / "nf_conntrack"
    p.write_text(V4_EST + "\n" + V6_EST + "\n")
    entries, source = read_entries(proc_file=str(p))
    assert source == "procfs"
    assert len(entries) == 2


def test_read_entries_netlink_fallback(tmp_path, monkeypatch):
    outputs = [FakeProc(0, V4_EST + "\n"), FakeProc(0, V6_EST + "\n")]
    calls = []

    def fake_run(args, **kw):
        calls.append(args)
        return outputs.pop(0)

    monkeypatch.setattr(conntrack.shutil, "which", lambda b: "/usr/sbin/conntrack")
    monkeypatch.setattr(conntrack.subprocess, "run", fake_run)
    entries, source = read_entries(proc_file=str(tmp_path / "missing"))
    assert source == "netlink"
    assert calls == [["conntrack", "-L"], ["conntrack", "-L", "-f", "ipv6"]]
    assert {e["family"] for e in entries} == {"ipv4", "ipv6"}


def test_read_entries_v6_dump_failure_nonfatal(tmp_path, monkeypatch):
    def fake_run(args, **kw):
        if args == ["conntrack", "-L"]:
            return FakeProc(0, V4_EST + "\n")
        return FakeProc(1, "", "ipv6 table not loaded")

    monkeypatch.setattr(conntrack.shutil, "which", lambda b: "/usr/sbin/conntrack")
    monkeypatch.setattr(conntrack.subprocess, "run", fake_run)
    entries, source = read_entries(proc_file=str(tmp_path / "missing"))
    assert source == "netlink" and len(entries) == 1


def test_read_entries_no_source(tmp_path, monkeypatch):
    monkeypatch.setattr(conntrack.shutil, "which", lambda b: None)
    with pytest.raises(FileNotFoundError, match="conntrack unavailable"):
        read_entries(proc_file=str(tmp_path / "missing"))


def test_read_entries_tool_failure(tmp_path, monkeypatch):
    monkeypatch.setattr(conntrack.shutil, "which", lambda b: "/usr/sbin/conntrack")
    monkeypatch.setattr(conntrack.subprocess, "run",
                        lambda args, **kw: FakeProc(1, "", "netlink error"))
    with pytest.raises(RuntimeError, match="netlink error"):
        read_entries(proc_file=str(tmp_path / "missing"))


def test_read_entries_timeout(tmp_path, monkeypatch):
    def fake_run(args, **kw):
        raise subprocess.TimeoutExpired(args, 15)

    monkeypatch.setattr(conntrack.shutil, "which", lambda b: "/usr/sbin/conntrack")
    monkeypatch.setattr(conntrack.subprocess, "run", fake_run)
    with pytest.raises(RuntimeError, match="timed out"):
        read_entries(proc_file=str(tmp_path / "missing"))


def test_deleted_count_summary_and_fallback():
    assert conntrack._deleted_count("2 flow entries have been deleted.") == 2
    assert conntrack._deleted_count("0 flow entries have been deleted.") == 0
    assert conntrack._deleted_count("2 entries deleted.") == 2
    # no summary (older tools echo only the deleted entries)
    assert conntrack._deleted_count("ipv4 tcp src=1.2.3.4 dst=5.6.7.8\n") == 1
    assert conntrack._deleted_count("") == 0


def test_flush_for_ips_runs_all_match_flags(monkeypatch):
    calls = []

    def fake_run(args, capture_output, text, timeout):
        calls.append(args)
        out = "1 flow entries have been deleted." if args[2] == "-s" \
            else "0 flow entries have been deleted."
        return subprocess.CompletedProcess(args, 0, stdout=out, stderr="")

    monkeypatch.setattr(conntrack.shutil, "which", lambda b: "/usr/sbin/conntrack")
    monkeypatch.setattr(conntrack.subprocess, "run", fake_run)
    res = conntrack.flush_for_ips({"172.18.0.5", ""})
    assert res["deleted"] == 1 and res["errors"] == []
    assert calls == [
        ["conntrack", "-D", "-s", "172.18.0.5"],
        ["conntrack", "-D", "-d", "172.18.0.5"],
        ["conntrack", "-D", "-r", "172.18.0.5"],
    ]


def test_flush_for_ips_records_errors_but_continues(monkeypatch):
    def fake_run(args, capture_output, text, timeout):
        if args[2] == "-r":  # e.g. an older tool without the -r flag
            return subprocess.CompletedProcess(args, 1, stdout="", stderr="unknown argument")
        return subprocess.CompletedProcess(args, 0, stdout="0 flow entries have been deleted.",
                                           stderr="")

    monkeypatch.setattr(conntrack.shutil, "which", lambda b: "/usr/sbin/conntrack")
    monkeypatch.setattr(conntrack.subprocess, "run", fake_run)
    res = conntrack.flush_for_ips(["fd00::5"])
    assert res["deleted"] == 0
    assert len(res["errors"]) == 1 and "-r" in res["errors"][0]


def test_flush_for_ips_nomatch_is_not_an_error(monkeypatch):
    """conntrack v1.4.x exits non-zero when nothing matched but still prints
    the summary — must count 0 and report no error."""
    def fake_run(args, capture_output, text, timeout):
        return subprocess.CompletedProcess(args, 1, stdout="0 flow entries have been deleted.",
                                           stderr="")

    monkeypatch.setattr(conntrack.shutil, "which", lambda b: "/usr/sbin/conntrack")
    monkeypatch.setattr(conntrack.subprocess, "run", fake_run)
    res = conntrack.flush_for_ips(["172.18.0.5"])
    assert res == {"deleted": 0, "errors": []}


def test_flush_for_ips_missing_binary(monkeypatch):
    monkeypatch.setattr(conntrack.shutil, "which", lambda b: None)
    with pytest.raises(FileNotFoundError):
        conntrack.flush_for_ips(["172.18.0.5"])
