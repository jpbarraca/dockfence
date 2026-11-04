"""Docker watcher: initial listing + event stream.

Resolves per container: name, image, labels, per-network IPv4/IPv6
addresses, networks/gateways, published ports and firewall eligibility.
Guards: never tags the firewall container itself; host-network containers
are flagged unfilterable.
"""

from __future__ import annotations

import socket
import threading
import time

from .config import Config


class DockerWatcher:
    def __init__(self, cfg: Config):
        self.cfg = cfg
        self.client = None
        self.self_id = socket.gethostname().strip()  # our own container (guard)
        self._snapshot: dict[str, dict] = {}
        self._lock = threading.Lock()
        self._stop = threading.Event()

    # -- docker client ------------------------------------------------------
    def _connect(self):
        import docker  # official SDK; imported lazily for test environments

        self.client = docker.DockerClient(base_url=f"unix://{self.cfg.docker_socket}")
        self.client.version()  # fail fast with a clear error

    def ping(self) -> dict:
        try:
            if self.client is None:
                self._connect()
            ver = self.client.version()
            return {"status": "ok", "version": ver.get("Version", "?")}
        except Exception as exc:  # noqa: BLE001
            return {"status": "error", "error": str(exc)}

    # -- resolution ---------------------------------------------------------
    def _resolve(self, attrs: dict) -> dict:
        cfg = self.cfg
        cid = attrs.get("Id", "")
        name = (attrs.get("Names") or [attrs.get("Name", "")])[0]
        if isinstance(name, str):
            name = name.lstrip("/")
        # docker SDK ≥7 list() returns full inspect payloads: labels live under
        # Config.Labels; older list entries carry a top-level Labels. Handle both.
        config = attrs.get("Config") or {}
        labels = attrs.get("Labels") or config.get("Labels") or {}
        state = attrs.get("State", "")
        if isinstance(state, dict):  # full inspect output
            state = state.get("Status", "")

        # opt-in via label; policy name from the .policy label or container name
        opt_in = cfg.label in labels
        policy = None
        if opt_in:
            policy = labels.get(f"{cfg.label}.policy") or name

        nets = []
        ips: list[str] = []
        ns = ((attrs.get("NetworkSettings") or {}).get("Networks")) or {}
        for net_name, net in ns.items():
            v4 = net.get("IPAddress") or ""
            v6 = net.get("GlobalIPv6Address") or ""
            nets.append(
                {
                    "name": net_name,
                    "iface": self._bridge_iface(net_name, net),
                    "v4": v4,
                    "v6": v6,
                    "gateway4": net.get("Gateway") or "",
                    "gateway6": net.get("IPv6Gateway") or "",
                }
            )
            if v4:
                ips.append(v4)
            if v6:
                ips.append(v6)

        ports = []
        for k, bindings in (((attrs.get("NetworkSettings") or {}).get("Ports")) or {}).items():
            for b in bindings or []:
                ports.append({"container": k, "host": f"{b.get('HostIp', '')}:{b.get('HostPort', '')}"})

        host_network = "host" in ns or (attrs.get("HostConfig") or {}).get("NetworkMode") == "host"
        is_self = bool(cid) and (cid == self.self_id or self.self_id.startswith(cid))

        return {
            "id": cid,
            "name": name,
            "image": config.get("Image") or attrs.get("Image", ""),
            "state": state,
            "labels": labels,
            "opt_in": bool(opt_in),
            "policy": policy,
            "networks": nets,
            "ips": ips,
            "ports": ports,
            "host_network": bool(host_network),
            "self": is_self,
        }

    @staticmethod
    def _bridge_iface(net_name: str, net: dict) -> str:
        """Best-effort host device name for a container network (UI display).
        Docker names user-defined bridges 'br-<first 12 chars of network id>';
        the default bridge is docker0; host/none carry no bridge device."""
        if net_name == "bridge":
            return "docker0"
        if net_name in ("host", "none"):
            return net_name
        net_id = net.get("NetworkID") or ""
        if len(net_id) >= 12:
            return f"br-{net_id[:12]}"
        return ""

    def unfilterable_reason(self, c: dict) -> str | None:
        if c.get("self"):
            return "firewall container itself (never tagged)"
        if c.get("host_network"):
            return "host network: no veth to filter"
        if c.get("state") != "running":
            return f"not running ({c.get('state')})"
        if not c.get("ips"):
            return "no IP addresses resolved"
        return None

    # -- snapshot -----------------------------------------------------------
    def refresh(self) -> list[dict]:
        """Full listing (one API call). Returns resolved container dicts."""
        if self.client is None:
            self._connect()
        out = []
        with self._lock:
            self._snapshot = {}
            for c in self.client.containers.list(all=True):
                resolved = self._resolve(c.attrs)
                self._snapshot[resolved["id"]] = resolved
                out.append(resolved)
        return out

    def refresh_one(self, cid: str) -> dict | None:
        """Inspect a single container and update the snapshot."""
        if self.client is None:
            self._connect()
        try:
            insp = self.client.containers.get(cid)
            resolved = self._resolve(insp.attrs)
        except Exception:  # removed/not found — drop from snapshot
            with self._lock:
                self._snapshot.pop(cid, None)
            return None
        with self._lock:
            self._snapshot[resolved["id"]] = resolved
        return resolved

    def snapshot(self) -> list[dict]:
        with self._lock:
            return list(self._snapshot.values())

    def get(self, cid: str) -> dict | None:
        with self._lock:
            c = self._snapshot.get(cid)
            if c is None:  # allow short id lookups
                for full, cand in self._snapshot.items():
                    if full.startswith(cid):
                        c = cand
                        break
        if c is None:
            c = self.refresh_one(cid)
        return c

    # -- event stream ---------------------------------------------------------
    def run(self, on_event, register_stop=None) -> None:
        """Background thread: docker events for containers + networks,
        auto-reconnecting with backoff. Each event triggers a resync."""
        while not self._stop.is_set():
            try:
                if self.client is None:
                    self._connect()
                events = self.client.events(
                    decode=True,
                    filters={"type": ["container", "network"]},
                    since=int(time.time()),
                )
                for ev in events:
                    if self._stop.is_set():
                        break
                    try:
                        on_event(ev)
                    except Exception as exc:  # never die from a handler
                        self._last_error = f"event handler error: {exc}"
            except Exception as exc:  # noqa: BLE001  stream broke — reconnect
                self._last_error = str(exc)
                if self._stop.wait(timeout=5):
                    break
        if register_stop:
            register_stop()

    def stop(self) -> None:
        self._stop.set()

    @property
    def last_error(self) -> str | None:
        return getattr(self, "_last_error", None)
