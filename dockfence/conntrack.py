"""Active traffic sessions from the host conntrack table (per-container view).

The kernel only exposes /proc/net/nf_conntrack with CONFIG_NF_CONNTRACK_PROCFS;
when it is compiled out (e.g. some ARM/embedded kernels) the `conntrack`
netlink tool (conntrack-tools) prints the same tuple format. The firewall
container runs in the host network namespace with CAP_NET_ADMIN, so both
sources see the host's connection tracking. Sessions are read-only; the only
write path is the explicit flush helper (flush_for_ips), which deletes
entries so pending rule changes re-evaluate established flows.

Entry format (both sources):
  ipv4 2 tcp 6 43199 ESTABLISHED src=172.18.0.5 dst=140.82.121.4 sport=41234 \
      dport=443 src=140.82.121.4 dst=172.18.0.1 sport=443 dport=41234 [ASSURED] mark=0 use=1
"""

from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path

PROC_FILE = "/proc/net/nf_conntrack"


def _kv(tokens: list[str]) -> dict[str, str]:
    out: dict[str, str] = {}
    for tok in tokens:
        if "=" in tok:
            key, _, val = tok.partition("=")
            out[key] = val
    return out


def _int(val: str | None) -> int | None:
    try:
        return int(val)
    except (TypeError, ValueError):
        return None


def _parse_line(line: str) -> dict | None:
    """One conntrack line → entry dict, or None for unparseable lines."""
    if "src=" not in line:
        return None
    positional: list[str] = []
    kv: list[str] = []
    assured = False
    for tok in line.split():
        if "=" in tok:
            kv.append(tok)
        elif tok == "[ASSURED]":
            assured = True
        elif tok.startswith("["):
            pass  # [UNREPLIED] and friends
        else:
            positional.append(tok)

    # positional tokens: [ipv4|ipv6] [ethertype] <proto> <pnum> <timeout> [STATE]
    family = ""
    proto = ""
    state = ""
    timeout = 0
    for tok in positional:
        if tok in ("ipv4", "ipv6"):
            family = tok
        elif tok.isdigit():
            timeout = int(tok)  # last numeric token wins
        elif not proto:
            proto = tok
        elif not state:
            state = tok

    # two tuples: original (initiator) then reply (only after a second src=)
    src_idx = [i for i, t in enumerate(kv) if t.startswith("src=")]
    if not src_idx:
        return None
    split = src_idx[1] if len(src_idx) > 1 else len(kv)
    orig = _kv(kv[src_idx[0]:split])
    reply = _kv(kv[split:]) if len(src_idx) > 1 else {}
    src = orig.get("src", "")
    if not src:
        return None
    return {
        "family": family or ("ipv6" if ":" in src else "ipv4"),
        "proto": proto,
        "state": state,
        "timeout": timeout,
        "assured": assured,
        "src": src,
        "sport": _int(orig.get("sport")),
        "dst": orig.get("dst", ""),
        "dport": _int(orig.get("dport")),
        "reply_src": reply.get("src", ""),
        "reply_sport": _int(reply.get("sport")),
        "reply_dst": reply.get("dst", ""),
        "reply_dport": _int(reply.get("dport")),
    }


def _parse_text(text: str) -> list[dict]:
    return [e for e in (_parse_line(line) for line in text.splitlines()) if e]


def read_entries(proc_file: str = PROC_FILE, binary: str = "conntrack") -> tuple[list[dict], str]:
    """All conntrack entries + which source served them ('procfs' | 'netlink').

    Raises OSError when neither source exists, RuntimeError when the tool
    fails. `conntrack -L` dumps ipv4 only, so the ipv6 table is appended
    separately (a failing v6 dump is non-fatal once v4 succeeded)."""
    path = Path(proc_file)
    if path.exists():
        try:
            return _parse_text(path.read_text(errors="replace")), "procfs"
        except OSError:
            pass  # unreadable procfs — try the netlink tool
    if shutil.which(binary) is None:
        raise FileNotFoundError(
            f"conntrack unavailable: no {proc_file} and no '{binary}' binary installed"
        )
    chunks: list[str] = []
    for args in ([binary, "-L"], [binary, "-L", "-f", "ipv6"]):
        try:
            proc = subprocess.run(args, capture_output=True, text=True, timeout=15)
        except subprocess.TimeoutExpired as exc:
            raise RuntimeError(f"{' '.join(args)} timed out") from exc
        if proc.returncode == 0 and proc.stdout:
            chunks.append(proc.stdout)
        elif not chunks:
            raise RuntimeError(f"{' '.join(args)} failed: {(proc.stderr or '').strip()}")
    return _parse_text("\n".join(chunks)), "netlink"


def sessions_for(entries: list[dict], ips: set[str], limit: int = 200) -> list[dict]:
    """Rows where one of the container's IPs is a session endpoint.

    'out' = container-initiated (container is the original source);
    'in' = the container is the original destination or the DNAT reply
    source (published ports). Established sessions sort first."""
    want = {ip for ip in ips if ip}
    rows: list[dict] = []
    for e in entries:
        if e["src"] in want:
            direction = "out"
        elif e["dst"] in want or e["reply_src"] in want:
            direction = "in"
        else:
            continue
        rows.append({
            "dir": direction,
            "family": e["family"],
            "proto": e["proto"],
            "state": e["state"],
            "src": e["src"],
            "sport": e["sport"],
            "dst": e["dst"],
            "dport": e["dport"],
            "timeout": e["timeout"],
            "assured": e["assured"],
            "reply_src": e["reply_src"],
        })
    rows.sort(key=lambda r: (r["state"] != "ESTABLISHED", r["proto"], r["src"], r["sport"] or 0))
    return rows[:limit]


# ------------------------------------------------------------ flush helper --

_DELETED_RE = re.compile(
    r"(\d+)\s+(?:flow\s+)?entr(?:y|ies)\s+(?:have\s+been\s+)?deleted", re.I)


def _deleted_count(text: str) -> int:
    """Deleted-entry count from `conntrack -D` output.

    conntrack-tools prints a summary ('N flow entries have been deleted.');
    when that is missing, fall back to counting the echoed entry lines."""
    m = _DELETED_RE.search(text)
    if m:
        return int(m.group(1))
    return sum(1 for line in text.splitlines() if "src=" in line)


def flush_for_ips(ips, binary: str = "conntrack", timeout: float = 15) -> dict:
    """Delete conntrack entries touching any of `ips` (flush helper).

    Established flows are not re-evaluated against a new ruleset, so a
    freshly applied deny rule does not affect connections opened before it.
    This deletes the tracked entries; the next packet re-creates them
    through the current rules (or is dropped). Requires the conntrack
    netlink tool — procfs cannot delete single entries.

    Per IP three match flags are used: original source ('-s', flows the
    container initiated), original destination ('-d', host-internal flows)
    and reply source ('-r', published-port DNAT flows). A failing flag
    (e.g. an older tool without -r) is recorded in "errors", never fatal;
    a no-match delete exits non-zero on some conntrack versions but is
    not an error when the summary line says 0 entries were deleted.

    Returns {"deleted": <int>, "errors": [str, ...]}."""
    if shutil.which(binary) is None:
        raise FileNotFoundError(
            f"conntrack flush unavailable: no '{binary}' binary installed "
            "(procfs cannot delete single entries)")
    want = {ip for ip in ips if ip}
    deleted = 0
    errors: list[str] = []
    for ip in want:
        for flag in ("-s", "-d", "-r"):
            args = [binary, "-D", flag, ip]
            try:
                proc = subprocess.run(args, capture_output=True, text=True,
                                      timeout=timeout)
            except subprocess.TimeoutExpired:
                errors.append(f"{' '.join(args)} timed out")
                continue
            out = proc.stdout + "\n" + proc.stderr
            if proc.returncode != 0 and _DELETED_RE.search(out) is None:
                err = out.strip().splitlines()
                errors.append(f"{' '.join(args)}: {err[-1] if err else 'failed'}")
                continue
            deleted += _deleted_count(out)
    return {"deleted": deleted, "errors": errors}
