"""NFLOG netlink message parsing: build synthetic kernel messages and
round-trip them through the consumer's parsers."""

import socket
import struct

import pytest

from dockfence.nflog import (
    EventBus,
    NFLogConsumer,
    NFULA_PAYLOAD,
    NFULA_PREFIX,
    NFULA_TIMESTAMP,
    NFNL_SUBSYS_ULOG,
    NFULNL_MSG_PACKET,
    build_bind_message,
    parse_ipv4,
    parse_ipv6,
    parse_packet_msg,
    parse_prefix,
)


def build_packet_msg(family: int, payload: bytes, prefix: bytes,
                     ts=(1700000000, 123456), indev=7) -> bytes:
    """Assemble a synthetic NFULNL_MSG_PACKET message like the kernel does."""
    attrs = b""
    if ts:
        attrs += struct.pack("<HH", 4 + 16, NFULA_TIMESTAMP) + struct.pack("!QQ", *ts)
    if indev:
        attrs += struct.pack("<HH", 4 + 4, 4) + struct.pack(">I", indev)  # IFINDEX_INDEV (be32)
    attrs += struct.pack("<HH", 4 + len(payload), NFULA_PAYLOAD) + payload
    attrs += struct.pack("<HH", 4 + len(prefix), NFULA_PREFIX) + prefix + b"\x00"
    if len(attrs) % 4:
        attrs += b"\x00" * (4 - len(attrs) % 4)

    nfgenmsg = struct.pack("<BBH", family, 0, socket.htons(5))
    body = nfgenmsg + attrs
    nlmsg_len = 16 + len(body)
    nlmsghdr = struct.pack("<IHHII", nlmsg_len, (NFNL_SUBSYS_ULOG << 8) | NFULNL_MSG_PACKET, 0, 2, 3)
    return nlmsghdr + body


def ipv4_payload(proto=6, sport=44444, dport=443, src="172.18.0.5", dst="203.0.113.4") -> bytes:
    return struct.pack(
        "!BBHHHBBH4s4sHH",
        0x45, 0, 40, 1234, 0, 64, proto, 0,
        socket.inet_aton(src), socket.inet_aton(dst), sport, dport,
    ) + b"\x00" * 8


def ipv6_payload(sport=53000, dport=53) -> bytes:
    src = socket.inet_pton(socket.AF_INET6, "fd12::5")
    dst = socket.inet_pton(socket.AF_INET6, "2001:db8::53")
    return struct.pack("!IHBB", 0x60000000, 0, 17, 64) + src + dst + struct.pack("!HH", sport, dport)


def test_prefix_parse():
    p = parse_prefix("DFW;c=abcdef123456;d=web;dir=out;")
    assert p == {"c": "abcdef123456", "d": "web", "dir": "out"}


def test_prefix_rejects_foreign():
    assert parse_prefix("other thing") is None
    assert parse_prefix("DFW;c=abc") is None  # missing dir
    assert parse_prefix("") is None


def test_ipv4_parse():
    r = parse_ipv4(ipv4_payload())
    assert r["family"] == 4
    assert r["src"] == "172.18.0.5" and r["dst"] == "203.0.113.4"
    assert r["proto"] == "tcp" and (r["sport"], r["dport"]) == (44444, 443)


def test_ipv6_parse():
    r = parse_ipv6(ipv6_payload())
    assert r["family"] == 6
    assert r["proto"] == "udp" and (r["sport"], r["dport"]) == (53000, 53)
    assert r["dst"] == "2001:db8::53"


def test_packet_msg_roundtrip():
    msg = build_packet_msg(socket.AF_INET, ipv4_payload(), b"DFW;c=abc123;d=web;dir=in;")
    r = parse_packet_msg(msg[16:])
    assert r["prefix"]["c"] == "abc123"
    assert r["prefix"]["dir"] == "in"
    assert r["src"] == "172.18.0.5" and r["dport"] == 443
    assert r["ts"] == 1700000000
    assert r["ifaces"] == ["7"]


def test_packet_msg_v6_family_from_nfgenmsg():
    msg = build_packet_msg(socket.AF_INET6, ipv6_payload(), b"DFW;c=abc123;d=db;dir=out;")
    r = parse_packet_msg(msg[16:])
    assert r["family"] == 6
    assert r["dport"] == 53


def test_foreign_group_messages_ignored():
    msg = build_packet_msg(socket.AF_INET, ipv4_payload(), b"iptables: some log")
    assert parse_packet_msg(msg[16:]) is None


def test_bind_message_shape():
    msg = build_bind_message(group=5, seq=1, pid=9)
    nl_len, nl_type, flags, seq, pid = struct.unpack_from("<IHHII", msg, 0)
    assert nl_len == len(msg)
    assert nl_type == (NFNL_SUBSYS_ULOG << 8) | 1
    assert flags & 0x01 and flags & 0x04  # REQUEST | ACK
    assert seq == 1 and pid == 9
    family, version, res_id = struct.unpack_from("<BBH", msg, 16)
    assert family == socket.AF_INET
    assert res_id == socket.htons(5)
    # attr: NFULA_CFG_CMD with u8 BIND command (length 5 = header 4 + u8, padded to 8)
    a_len, a_type = struct.unpack_from("<HH", msg, 20)
    assert a_len == 5 and a_type == 1
    assert msg[24] == 1  # NFULNL_CFG_CMD_BIND


def test_partial_and_garbage_tolerated():
    assert parse_packet_msg(b"\x00" * 3) is None
    msg = build_packet_msg(socket.AF_INET, b"garbage", b"DFW;c=x;d=y;dir=in;")
    assert parse_packet_msg(msg[16:]) is None  # unparsable payload dropped


def test_dns_new_pair_triggers_apply(cfg, store):
    """A NEW (name, ip) pair for a name referenced by an enabled dns-rule
    fires on_dns_change (wired to the controller's re-apply); refreshes of
    known pairs and unreferenced names do not."""
    pid = store.get_or_create_policy("web")
    store.add_rule(pid, {"direction": "out", "proto": "tcp", "port": 443,
                         "action": "accept", "dns": "example.com"})
    consumer = NFLogConsumer(cfg, store, EventBus())
    seen: list[set[str]] = []
    consumer.on_dns_change = lambda names: seen.append(names)
    # new pair → pending; refresh → not pending; unrelated name → filtered out
    assert store.upsert_dns("example.com", "203.0.113.4", ts=1000) is True
    assert store.upsert_dns("example.com", "203.0.113.4", ts=1010) is False
    assert store.upsert_dns("unrelated.example", "203.0.113.9", ts=1010) is True
    consumer._dns_pending |= {"example.com", "unrelated.example"}
    consumer._drain_dns_pending()
    assert seen == [{"example.com"}]
    assert consumer._dns_pending == set()
