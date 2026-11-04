"""DNS answer parsing + consumer dispatch.

Synthesizes DNS response messages (A/AAAA/CNAME, compression pointers,
DNS-over-TCP length prefix) and round-trips them through the parsers and
the NFLogConsumer's dns path."""

import socket
import struct

import pytest

from dockfence.config import Config
from dockfence.dnslog import DNS_LOG_PREFIX, l4_payload_offset, parse_dns_answers
from dockfence.nflog import (
    NFULA_PAYLOAD,
    NFULA_PREFIX,
    NFNL_SUBSYS_ULOG,
    NFULNL_MSG_PACKET,
    EventBus,
    NFLogConsumer,
    parse_packet_msg,
)


def _attr(nla_type: int, data: bytes) -> bytes:
    """One netlink attribute, 4-byte aligned like the kernel emits them."""
    raw = struct.pack("<HH", 4 + len(data), nla_type) + data
    if len(raw) % 4:
        raw += b"\x00" * (4 - len(raw) % 4)
    return raw


def build_packet_msg(family: int, payload: bytes, prefix: bytes) -> bytes:
    """Assemble a synthetic NFULNL_MSG_PACKET message like the kernel does
    (same helper as test_nflog; duplicated to keep modules independent)."""
    attrs = _attr(3, struct.pack("!QQ", 1700000000, 123456))  # NFULA_TIMESTAMP
    attrs += _attr(4, struct.pack(">I", 7))  # NFULA_IFINDEX_INDEV (be32)
    attrs += _attr(NFULA_PAYLOAD, payload)
    attrs += _attr(NFULA_PREFIX, prefix + b"\x00")
    nfgenmsg = struct.pack("<BBH", family, 0, socket.htons(1))
    body = nfgenmsg + attrs
    return struct.pack("<IHHII", 16 + len(body),
                       (NFNL_SUBSYS_ULOG << 8) | NFULNL_MSG_PACKET, 0, 2, 3) + body


def enc_name(name: str) -> bytes:
    out = b""
    for label in name.split("."):
        if label:
            out += bytes([len(label)]) + label.encode()
    return out + b"\x00"


def dns_message(answers: list[tuple[str, int, bytes]], qname="example.com") -> bytes:
    """Build a DNS response: question + answer records (name, rtype, rdata)."""
    msg = struct.pack("!HHHHHH", 0x1234, 0x8180, 1, len(answers), 0, 0)
    msg += enc_name(qname) + struct.pack("!HH", 1, 1)
    for name, rtype, rdata in answers:
        msg += enc_name(name) + struct.pack("!HHIH", rtype, 1, 60, len(rdata)) + rdata
    return msg


def udp_packet(src="192.168.1.1", dst="172.18.0.5", sport=53, dport=44444,
               payload: bytes | None = None) -> bytes:
    body = payload or b""
    udp = struct.pack("!HHHH", sport, dport, 8 + len(body), 0)
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 28 + len(body), 1, 0,
                     64, 17, 0, socket.inet_aton(src), socket.inet_aton(dst))
    return ip + udp + body


def tcp_packet(src="192.168.1.1", dst="172.18.0.5", sport=53, dport=44444,
               payload: bytes | None = None) -> bytes:
    body = payload or b""
    tcp = struct.pack("!HHIIBBHHH", sport, dport, 1, 0, 0x50, 0x18, 8192, 0, 0)
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 40 + len(body), 1, 0,
                     64, 6, 0, socket.inet_aton(src), socket.inet_aton(dst))
    return ip + tcp + body


def test_a_record_parsed():
    msg = dns_message([("example.com", 1, socket.inet_aton("93.184.216.34"))])
    assert parse_dns_answers(msg) == [("example.com", "93.184.216.34")]


def test_aaaa_record_parsed():
    rdata = socket.inet_pton(socket.AF_INET6, "2606:2800:220:1::1")
    assert parse_dns_answers(dns_message([("example.com", 28, rdata)])) == \
        [("example.com", "2606:2800:220:1::1")]


def test_cname_alias_maps_to_ip():
    """www.example.com CNAME example.com + A example.com → both names map."""
    a_rdata = socket.inet_aton("93.184.216.34")
    header = struct.pack("!HHHHHH", 0x1234, 0x8180, 1, 2, 0, 0)
    msg = header + enc_name("www.example.com") + struct.pack("!HH", 1, 1)
    # CNAME rdata uses a compression pointer back to the question name
    msg += enc_name("www.example.com") + struct.pack("!HHIH", 5, 1, 60, 2) + b"\xc0\x10"
    # A record owned by the compression target (offset 0x10 = 16)
    msg += b"\xc0\x10" + struct.pack("!HHIH", 1, 1, 60, 4) + a_rdata
    pairs = parse_dns_answers(msg)
    assert ("www.example.com", "93.184.216.34") in pairs
    assert ("example.com", "93.184.216.34") in pairs


def test_tcp_length_prefix_stripped():
    msg = dns_message([("example.com", 1, socket.inet_aton("93.184.216.34"))])
    framed = struct.pack("!H", len(msg)) + msg
    assert parse_dns_answers(framed, tcp=True) == [("example.com", "93.184.216.34")]


def test_garbage_and_truncation_tolerated():
    assert parse_dns_answers(b"") == []
    assert parse_dns_answers(b"\x00" * 11) == []
    assert parse_dns_answers(b"garbage-garbage!") == []
    # question-only message (no answers)
    header = struct.pack("!HHHHHH", 1, 0, 1, 0, 0, 0)
    assert parse_dns_answers(header + enc_name("a.b") + struct.pack("!HH", 1, 1)) == []


def test_l4_payload_offset():
    payload = b"DNSPAYLOAD"
    pkt = udp_packet(payload=payload)
    off = l4_payload_offset(pkt, 4, 17)
    assert pkt[off:] == payload
    pkt = tcp_packet(payload=payload)
    off = l4_payload_offset(pkt, 4, 6)
    assert pkt[off:] == payload
    # ipv6 + udp
    v6 = struct.pack("!IHBB", 0x60000000, 0, 17, 64) \
        + socket.inet_pton(socket.AF_INET6, "fd00::1") \
        + socket.inet_pton(socket.AF_INET6, "fd00::2") \
        + struct.pack("!HHHH", 53, 44444, 8 + len(payload), 0) + payload
    off = l4_payload_offset(v6, 6, 17)
    assert v6[off:] == payload
    # non-udp/tcp and garbage → None
    assert l4_payload_offset(b"xx", 4, 1) is None
    assert l4_payload_offset(b"", 4, 17) is None


def test_packet_msg_dns_dispatch():
    payload = udp_packet(payload=dns_message(
        [("test.example", 1, socket.inet_aton("203.0.113.9"))]))
    msg = build_packet_msg(socket.AF_INET, payload, DNS_LOG_PREFIX.encode())
    parsed = parse_packet_msg(msg[16:])
    assert parsed["dns"] is True
    assert parsed["src"] == "192.168.1.1"  # the resolver
    off = l4_payload_offset(parsed["payload"], parsed["family"], parsed["proto_num"])
    assert parse_dns_answers(parsed["payload"][off:]) == [("test.example", "203.0.113.9")]


def test_consumer_stores_dns_answers(cfg, store):
    store.set_settings({"dns_log": True})
    consumer = NFLogConsumer(cfg, store, EventBus())
    payload = udp_packet(payload=dns_message([
        ("service.example", 1, socket.inet_aton("198.51.100.7")),
        ("service.example", 28, socket.inet_pton(socket.AF_INET6, "2001:db8::7")),
    ]))
    consumer._handle(build_packet_msg(socket.AF_INET, payload, DNS_LOG_PREFIX.encode()))
    rows = {r["name"]: r for r in store.dns_mappings()}
    assert set(rows) == {"service.example"}
    assert rows["service.example"]["resolver"] == "192.168.1.1"
    assert store.dns_counts()["events"] == 2
    assert consumer.status.dns == 2
    # setting off → nothing further stored even if kernel rules were left over
    store.set_settings({"dns_log": False})
    consumer._handle(build_packet_msg(socket.AF_INET, payload, DNS_LOG_PREFIX.encode()))
    assert store.dns_counts()["events"] == 2


def test_consumer_annotates_log_rows_with_names(cfg, store):
    store.upsert_dns("github.com", "140.82.121.4", "192.168.1.1")
    consumer = NFLogConsumer(cfg, store, EventBus())
    ipv4 = struct.pack("!BBHHHBBH4s4sHH", 0x45, 0, 40, 1, 0, 64, 6, 0,
                       socket.inet_aton("172.18.0.5"), socket.inet_aton("140.82.121.4"),
                       44444, 443) + b"\x00" * 8
    msg = build_packet_msg(socket.AF_INET, ipv4, b"DFW;c=abc123def456;d=web;dir=out;")
    consumer._handle(msg)
    assert consumer.status.stored == 1
    # firewall rows still parse exactly as before (dns flag absent)
    from dockfence.nflog import parse_packet_msg as pp
    assert pp(msg[16:])["dst"] == "140.82.121.4"


@pytest.fixture
def cfg(tmp_path):
    return Config(token="x", db_path=str(tmp_path / "t.db"))
