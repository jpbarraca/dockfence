"""nflog consumer: netlink NFNETLINK-ULOG (NFLOG) group subscriber.

Pure-Python netlink client (AF_NETLINK/NETLINK_NETFILTER) — parses kernel
NFULA messages, extracts the dockfence prefix + packet header fields and
writes one log row per blocked attempt.

Attribute numbers verified against linux/netfilter/nfnetlink_log.h.
"""

from __future__ import annotations

import fcntl
import queue
import socket
import struct
import threading
import time
from dataclasses import dataclass

from .dnslog import DNS_LOG_PREFIX, l4_payload_offset, parse_dns_answers

NETLINK_NETFILTER = 12
SOL_NETLINK = 270
NETLINK_NO_ENOBUFS = 6

NFNL_SUBSYS_ULOG = 4
NFULNL_MSG_PACKET = 0
NFULNL_MSG_CONFIG = 1

NFULA_PACKET_HDR = 1
NFULA_MARK = 2
NFULA_TIMESTAMP = 3
NFULA_IFINDEX_INDEV = 4
NFULA_IFINDEX_OUTDEV = 5
NFULA_IFINDEX_PHYSINDEV = 6
NFULA_IFINDEX_PHYSOUTDEV = 7
NFULA_PAYLOAD = 9
NFULA_PREFIX = 10

NFULNL_CFG_CMD_BIND = 1
NFULA_CFG_CMD = 1

NLMSG_ERROR = 2
NLA_F_NESTED = 0x8000

PROTONAMES = {1: "icmp", 6: "tcp", 17: "udp", 58: "ipv6-icmp"}


class NFLogBindError(Exception):
    pass


# ---------------------------------------------------------------- parsing ----
def parse_prefix(prefix: str) -> dict | None:
    """Parse 'DFW;c=<shortid>;d=<policy>;dir=<in|out>;' -> dict or None."""
    parts = [p for p in prefix.rstrip("\x00").split(";") if p]
    if not parts or parts[0] != "DFW":
        return None
    out: dict = {}
    for part in parts[1:]:
        if "=" in part:
            k, _, v = part.partition("=")
            out[k] = v
    if "c" not in out or out.get("dir") not in ("in", "out"):
        return None
    return out


def parse_ipv4(payload: bytes) -> dict | None:
    """Parse an IPv4 packet header into src/dst/proto/sport/dport."""
    if len(payload) < 20 or payload[0] >> 4 != 4:
        return None
    ihl = (payload[0] & 0xF) * 4
    if ihl < 20 or len(payload) < ihl:
        return None
    proto = payload[9]
    src = socket.inet_ntop(socket.AF_INET, payload[12:16])
    dst = socket.inet_ntop(socket.AF_INET, payload[16:20])
    sport = dport = None
    if proto in (6, 17, 132) and len(payload) >= ihl + 4:
        sport, dport = struct.unpack_from("!HH", payload, ihl)
    return {
        "family": 4,
        "src": src,
        "dst": dst,
        "proto": PROTONAMES.get(proto, str(proto)),
        "proto_num": proto,
        "sport": sport,
        "dport": dport,
    }


def parse_ipv6(payload: bytes) -> dict | None:
    if len(payload) < 40 or payload[0] >> 4 != 6:
        return None
    src = socket.inet_ntop(socket.AF_INET6, payload[8:24])
    dst = socket.inet_ntop(socket.AF_INET6, payload[24:40])
    proto = payload[6]
    sport = dport = None
    # no extension-header traversal for v1 — TCP/UDP/ICMPv6 first header
    if proto in (6, 17, 132) and len(payload) >= 44:
        sport, dport = struct.unpack_from("!HH", payload, 40)
    return {
        "family": 6,
        "src": src,
        "dst": dst,
        "proto": PROTONAMES.get(proto, str(proto)),
        "proto_num": proto,
        "sport": sport,
        "dport": dport,
    }


def parse_packet_msg(data: bytes) -> dict | None:
    """Parse one NFULNL_MSG_PACKET netlink message (after nlmsghdr)."""
    if len(data) < 4:
        return None
    family, _version, _res_id = struct.unpack_from("<BBH", data, 0)
    attrs = {}
    off = 4
    end = len(data)
    while off + 4 <= end:
        nla_len, nla_type = struct.unpack_from("<HH", data, off)
        if nla_len < 4 or off + nla_len > end:
            break
        attrs[nla_type & ~NLA_F_NESTED] = data[off + 4 : off + nla_len]
        off += (nla_len + 3) & ~3

    prefix_raw = attrs.get(NFULA_PREFIX, b"")
    prefix = prefix_raw.decode("utf-8", "replace") if prefix_raw else ""
    is_dns = prefix.startswith(DNS_LOG_PREFIX)
    info = parse_prefix(prefix)
    if info is None and not is_dns:
        return None  # not ours (some other nflog user on this group)

    payload = attrs.get(NFULA_PAYLOAD, b"")
    parsed = parse_ipv4(payload) if family == socket.AF_INET else parse_ipv6(payload)
    if parsed is None and payload:
        parsed = parse_ipv6(payload) if family == socket.AF_INET else parse_ipv4(payload)
    if parsed is None:
        return None  # unparsable payload (truncated/garbage) — drop it

    ts = int(time.time())
    if NFULA_TIMESTAMP in attrs and len(attrs[NFULA_TIMESTAMP]) >= 16:
        sec, usec = struct.unpack_from("!QQ", attrs[NFULA_TIMESTAMP])
        ts = int(sec)

    if is_dns:
        # DNS answer capture: the full packet payload is needed to parse
        # the response message (name<->ip pairs live in the answer section)
        return {"dns": True, "payload": payload, "ts": ts, **parsed}

    ifaces = []
    for attr in (NFULA_IFINDEX_INDEV, NFULA_IFINDEX_OUTDEV):
        if attr in attrs and len(attrs[attr]) == 4:
            idx = struct.unpack(">I", attrs[attr])[0]  # kernel sends be32
            if idx:
                ifaces.append(str(idx))

    return {
        "prefix": info,
        "ts": ts,
        "ifaces": ifaces,
        **parsed,
    }


def build_bind_message(group: int, seq: int = 1, pid: int = 0) -> bytes:
    """Config message subscribing us to an NFLOG group."""
    nfgenmsg = struct.pack("<BB", socket.AF_INET, 0) + struct.pack("!H", group)
    attr = struct.pack("<HH", 5, NFULA_CFG_CMD) + struct.pack("<B", NFULNL_CFG_CMD_BIND) + b"\x00"
    body = nfgenmsg + attr
    nlmsg_len = 16 + len(body)
    nlmsghdr = struct.pack("<IHHII", nlmsg_len, (NFNL_SUBSYS_ULOG << 8) | NFULNL_MSG_CONFIG,
                           0x105, seq, pid)  # NLM_F_REQUEST|NLM_F_ACK
    return nlmsghdr + body


# --------------------------------------------------------------- consumer ----
@dataclass
class NFLogStatus:
    bound: bool = False
    error: str | None = None
    received: int = 0
    stored: int = 0
    dropped: int = 0  # netlink queue overruns (log lines, never enforcement)
    dns: int = 0  # dns name<->ip pairs learned from captured answers


class NFLogConsumer:
    def __init__(self, cfg, store, bus, on_row=None):
        self.cfg = cfg
        self.store = store
        self.bus = bus
        self.on_row = on_row  # optional extra callback(row dict)
        # dns-rule auto-apply: names with NEW (name, ip) pairs, drained by
        # run_dns_rules() (debounced) into on_dns_change — wired to the
        # controller's re-apply so dns-rule kernel sets pick up new IPs
        self.on_dns_change = None  # optional callback(names set[str])
        self._dns_pending: set[str] = set()
        self._pending_lock = threading.Lock()
        self.status = NFLogStatus()
        self._sock: socket.socket | None = None
        self._stop = threading.Event()
        self._ifname_cache: dict[int, str] = {}
        self._ifname_fd: int | None = None

    # -- interface name resolution -----------------------------------------
    def _ifname(self, idx: int) -> str:
        if idx in self._ifname_cache:
            return self._ifname_cache[idx]
        name = str(idx)
        try:
            if self._ifname_fd is None:
                self._ifname_fd = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            buf = bytearray(40)  # struct ifreq
            struct.pack_into("i", buf, 16, idx)  # ifr_ifindex in the union
            fcntl.ioctl(self._ifname_fd, 0x8910, buf)  # SIOCGIFNAME
            name = bytes(buf[:16]).split(b"\x00")[0].decode("ascii", "replace") or name
        except OSError:
            pass
        if len(self._ifname_cache) > 512:
            self._ifname_cache.clear()
        self._ifname_cache[idx] = name
        return name

    # -- socket --------------------------------------------------------------
    def _bind(self) -> None:
        s = socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, NETLINK_NETFILTER)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4 << 20)
        try:
            s.setsockopt(SOL_NETLINK, NETLINK_NO_ENOBUFS, 1)
        except OSError:
            pass  # older kernels: we handle ENOBUFS explicitly
        s.bind((0, 0))
        pid = s.getsockname()[0]
        # packet logs on cfg.log_group; dns answer capture on the next group.
        # dns bind failure must not take down packet logging (best effort).
        for group, critical in ((self.cfg.log_group, True), (self.cfg.dns_group, False)):
            try:
                self._bind_group(s, group, pid)
            except NFLogBindError as exc:
                if critical:
                    raise
                self.store.add_event(
                    "nflog", f"dns capture group {group} unavailable: {exc}"
                )
        s.settimeout(None)
        self._sock = s
        self.status.bound = True
        self.status.error = None

    def _bind_group(self, s: socket.socket, group: int, pid: int) -> None:
        s.send(build_bind_message(group, pid=pid))
        # wait briefly for the ack
        s.settimeout(5)
        try:
            data = s.recv(65535)
            hdr = struct.unpack_from("<IHHII", data, 0)
            if hdr[1] == NLMSG_ERROR:
                err = struct.unpack_from("<i", data, 16)[0]
                if err != 0:
                    raise NFLogBindError(
                        f"nflog bind to group {group} failed: errno {-err}"
                    )
        except socket.timeout:
            pass  # no ack yet; assume bound (acks can be coalesced)

    def close(self) -> None:
        self._stop.set()
        if self._sock:
            try:
                self._sock.close()
            except OSError:
                pass
            self._sock = None

    # -- main loop -------------------------------------------------------------
    def run(self) -> None:
        try:
            self._bind()
        except Exception as exc:  # noqa: BLE001
            self.status.error = f"nflog unavailable: {exc}"
            self.store.add_event("nflog", self.status.error)
            return
        self.store.add_event("nflog", f"listening on nflog group {self.cfg.log_group}")
        while not self._stop.is_set():
            try:
                data = self._sock.recv(65535)
            except OSError as exc:
                if self._stop.is_set():
                    break
                if exc.errno == 105:  # ENOBUFS — kernel queue overrun
                    self.status.dropped += 1
                    continue
                self.status.error = str(exc)
                break
            self._handle(data)
        self.status.bound = False

    def _handle(self, data: bytes) -> None:
        off, size = 0, len(data)
        while off + 16 <= size:
            nl_len, nl_type, _fl, _seq, _pid = struct.unpack_from("<IHHII", data, off)
            if nl_len < 16:
                break
            msg = data[off : off + nl_len]
            off += (nl_len + 3) & ~3
            if (nl_type & 0xFF) != NFULNL_MSG_PACKET or (nl_type >> 8) != NFNL_SUBSYS_ULOG:
                continue
            try:
                parsed = parse_packet_msg(msg[16:])
            except Exception:  # malformed packet — never crash the consumer
                continue
            if not parsed:
                continue
            if parsed.get("dns"):
                self._store_dns(parsed)
            else:
                self.status.received += 1
                self._store_row(parsed)

    def _store_dns(self, parsed: dict) -> None:
        """Parse a captured DNS answer and learn name<->ip mappings."""
        try:
            if not self.store.get_bool_setting("dns_log", False):
                return  # capture toggled off — kernel rules are the real gate
            payload = parsed.get("payload") or b""
            off = l4_payload_offset(payload, parsed["family"], parsed["proto_num"])
            if off is None:
                return
            answers = parse_dns_answers(
                payload[off:], tcp=parsed["proto_num"] == 6
            )
            if not answers:
                return
            resolver, ts = parsed["src"], parsed["ts"]
            new_names: set[str] = set()
            for name, ip in answers:
                if self.store.upsert_dns(name, ip, resolver, ts):
                    new_names.add(name)  # new pair — kernel sets are stale
            if new_names:
                with self._pending_lock:
                    self._dns_pending |= new_names
            self.status.dns += len(answers)
        except Exception as exc:  # noqa: BLE001 — never kill the consumer
            self.status.error = f"dns store failed: {exc}"

    def _drain_dns_pending(self) -> None:
        """Re-apply when a NEW pair touches a name an enabled dns-rule
        references. Runs OFF the packet path (drained every 2 s)."""
        with self._pending_lock:
            names = set(self._dns_pending)
            self._dns_pending.clear()
        if not names:
            return
        try:
            referenced = self.store.dns_rule_names()
        except Exception:  # noqa: BLE001 — db hiccup: retry on next drain
            return
        hit = names & referenced
        if hit and self.on_dns_change:
            try:
                self.on_dns_change(hit)
            except Exception:  # noqa: BLE001 — apply failure is recorded there
                pass

    def run_dns_rules(self) -> None:
        """Debounced dns-rule apply loop: drains new DNS pairs every 2 s."""
        while not self._stop.wait(2.0):
            self._drain_dns_pending()

    def _store_row(self, parsed: dict) -> None:
        info = parsed["prefix"]
        cid = info.get("c", "")  # short id from the kernel prefix
        dirn = info["dir"]
        policy = info.get("d", "")
        container = self.store.get_container(cid) or {}
        row = {
            "ts": parsed["ts"],
            # store under the full container id (prefix resolves via the store)
            "container_id": container.get("id") or cid,
            "policy_id": container.get("policy_id"),
            "dir": dirn,
            "family": parsed["family"],
            "src": parsed["src"],
            "dst": parsed["dst"],
            "proto": parsed["proto"],
            "sport": parsed["sport"],
            "dport": parsed["dport"],
            "rule_id": None,
            "ifaces": ",".join(self._ifname(int(i)) for i in parsed["ifaces"]),
        }
        try:
            self.store.insert_log(row)
        except Exception as exc:  # noqa: BLE001
            self.status.error = f"log insert failed: {exc}"
        self.status.stored += 1
        row["policy"] = policy
        row["container_name"] = container.get("name", "")
        # hostname hints from the DNS mapping (embedded docker DNS answers
        # surface on the host path, so the mapping is global by design)
        row["dst_name"] = self.store.name_for_ip(row["dst"])
        row["src_name"] = self.store.name_for_ip(row["src"])
        try:
            self.bus.publish(row)
        except Exception:
            pass
        if self.on_row:
            try:
                self.on_row(row)
            except Exception:
                pass


# -------------------------------------------------------------------- bus ----
class EventBus:
    """Fan-out of live log rows to SSE subscribers."""

    def __init__(self, max_queue: int = 1000):
        self._subs: list[queue.Queue] = []
        self._lock = threading.Lock()
        self._max = max_queue

    def subscribe(self) -> queue.Queue:
        q: queue.Queue = queue.Queue(maxsize=self._max)
        with self._lock:
            self._subs.append(q)
        return q

    def unsubscribe(self, q: queue.Queue) -> None:
        with self._lock:
            if q in self._subs:
                self._subs.remove(q)

    def publish(self, row: dict) -> None:
        with self._lock:
            subs = list(self._subs)
        for q in subs:
            try:
                q.put_nowait(row)
            except queue.Full:
                pass  # slow subscriber: drop live lines, history stays in DB
