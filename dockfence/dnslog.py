"""DNS answer parsing for the capture path (NFLOG group = log_group + 1).

Captured packets are DNS *responses* (the answer direction) seen leaving or
entering this host. We extract A/AAAA mappings (following CNAME aliases) so
firewall log destinations can be shown with their hostnames.

Why the host path: Docker's embedded DNS (127.0.0.11 inside each container)
proxies lookups through dockerd in the HOST netns — the answers to containers
never cross a bridge, so per-container capture cannot see them. Capturing on
the host input/forward hooks sees every answer (embedded-DNS ones included);
the learned mapping is global, and matched against per-container firewall
logs by destination IP. See README "Egress & anti-exfiltration".

Best effort by design: malformed/truncated/garbage messages yield nothing
and are never allowed to disturb the firewall path.
"""

from __future__ import annotations

import socket

# kernel log prefix for dns capture rules (rendered by nft.py, parsed here)
DNS_LOG_PREFIX = "DFW;dns;"

# record types we care about
RTYPE_A = 1
RTYPE_CNAME = 5
RTYPE_AAAA = 28


def _read_name(msg: bytes, off: int) -> tuple[str | None, int | None]:
    """Decode a (possibly compression-pointer) domain name from a DNS message.
    Returns (name, offset_after_name) or (None, None) on malformed input."""
    labels: list[str] = []
    pos, end, jumps = off, None, 0
    while True:
        if pos >= len(msg):
            return None, None
        ln = msg[pos]
        if ln == 0:
            pos += 1
            end = pos if end is None else end
            break
        if ln & 0xC0:  # compression pointer (RFC 1035 §4.1.4)
            if pos + 2 > len(msg):
                return None, None
            ptr = ((ln & 0x3F) << 8) | msg[pos + 1]
            if end is None:
                end = pos + 2
            pos = ptr
            jumps += 1
            if jumps > 32 or pos >= len(msg):
                return None, None
            continue
        if pos + 1 + ln > len(msg):
            return None, None
        labels.append(msg[pos + 1 : pos + 1 + ln].decode("ascii", "replace"))
        pos += 1 + ln
    return ".".join(l for l in labels if l), end


def parse_dns_answers(payload: bytes, tcp: bool = False) -> list[tuple[str, str]]:
    """Extract (name, ip) pairs from one DNS response message.

    Handles A + AAAA records and CNAME aliases (compression pointers resolve
    against the full message). Duplicate pairs are removed, order preserved.
    """
    if tcp:
        # DNS-over-TCP prefixes the message with a 2-byte length
        if len(payload) < 2:
            return []
        payload = payload[2:]
    if len(payload) < 12:
        return []
    qdcount = int.from_bytes(payload[4:6], "big")
    ancount = int.from_bytes(payload[6:8], "big")
    off = 12
    out: list[tuple[str, str]] = []
    aliases: list[str] = []
    for _ in range(min(qdcount, 16)):
        _, off = _read_name(payload, off)
        if off is None or off + 4 > len(payload):
            return _dedupe(out)
        off += 4  # qtype + qclass
    for _ in range(min(ancount, 64)):
        name, off = _read_name(payload, off)
        if off is None or off + 10 > len(payload):
            break
        rtype = int.from_bytes(payload[off : off + 2], "big")
        rdlen = int.from_bytes(payload[off + 8 : off + 10], "big")
        rdata_off = off + 10
        off = rdata_off + rdlen
        if rtype == RTYPE_CNAME:
            # CNAME chain: the record's OWNER is the alias that will resolve
            # to the IP of the following A/AAAA record (whose owner is the
            # CNAME target). rdata itself needs no parsing.
            if name:
                aliases.append(name)
        elif rtype == RTYPE_A and rdlen == 4:
            ip = ".".join(str(b) for b in payload[rdata_off : rdata_off + 4])
            for n in (*aliases, name):
                if n:
                    out.append((n, ip))
            aliases = []
        elif rtype == RTYPE_AAAA and rdlen == 16:
            ip = socket.inet_ntop(socket.AF_INET6, payload[rdata_off : rdata_off + 16])
            for n in (*aliases, name):
                if n:
                    out.append((n, ip))
            aliases = []
    return _dedupe(out)


def _dedupe(pairs: list[tuple[str, str]]) -> list[tuple[str, str]]:
    seen: set[tuple[str, str]] = set()
    out = []
    for pair in pairs:
        if pair not in seen:
            seen.add(pair)
            out.append(pair)
    return out


def l4_payload_offset(payload: bytes, family: int, proto_num: int) -> int | None:
    """Offset of the L4 payload (past IP + transport headers) in a captured
    packet. family is 4 or 6; proto_num the IP protocol number."""
    if family == 4:
        if len(payload) < 20 or payload[0] >> 4 != 4:
            return None
        l4 = (payload[0] & 0xF) * 4
        if l4 < 20 or len(payload) < l4:
            return None
    else:
        l4 = 40
        if len(payload) < l4:
            return None
    if proto_num == 6:  # tcp — skip the data-offset-sized header
        if len(payload) < l4 + 13:
            return None
        doff = (payload[l4 + 12] >> 4) * 4
        if doff < 20 or len(payload) < l4 + doff:
            return None
        l4 += doff
    elif proto_num == 17:  # udp
        l4 += 8
    else:
        return None
    return l4
