"""Configuration from environment variables (see compose.yaml / README)."""

from __future__ import annotations

import os
import re
import secrets
from dataclasses import dataclass, field

MODES = ("enforcing", "monitor", "disabled")


class ConfigError(Exception):
    pass


def parse_duration(text: str) -> float:
    """Parse '30s', '5m', '1000ms', '1h' or bare seconds into seconds."""
    m = re.fullmatch(r"\s*(\d+(?:\.\d+)?)\s*(ms|s|m|h)?\s*", text)
    if not m:
        raise ConfigError(f"invalid duration: {text!r}")
    val = float(m.group(1))
    mult = {"ms": 0.001, "s": 1.0, "m": 60.0, "h": 3600.0, None: 1.0}[m.group(2)]
    return val * mult


def parse_log_limit(text: str) -> tuple[int, str, int]:
    """Parse '10/second' -> (rate=10, unit='second', burst=20)."""
    m = re.fullmatch(r"\s*(\d+)\s*/\s*(second|minute|hour|day)\s*", text)
    if not m:
        raise ConfigError(f"invalid FW_LOG_LIMIT: {text!r} (want e.g. '10/second')")
    rate = int(m.group(1))
    return rate, m.group(2), 2 * rate


def _env(name: str, default: str) -> str:
    return os.environ.get(name, default).strip()


@dataclass
class Config:
    label: str = "dockfence"
    mode: str = "enforcing"
    listen: str = "127.0.0.1:8420"
    filter_host: bool = True
    log_group: int = 5
    reconcile: float = 30.0
    log_rate: int = 10
    log_rate_unit: str = "second"
    log_burst: int = 20
    retention_days: int = 30
    retention_max_rows: int = 500_000
    event_retention_days: int = 7
    ipv6: bool = False
    token: str = field(default="")
    tls_cert: str = ""
    tls_key: str = ""
    docker_socket: str = "/var/run/docker.sock"
    db_path: str = "/var/lib/dockfence/dockfence.db"
    table: str = "dockfence"
    nft_binary: str = "nft"

    @classmethod
    def from_env(cls, env: dict | None = None) -> "Config":
        env = os.environ if env is None else env

        def get(name: str, default: str) -> str:
            return env.get(name, default).strip()

        def truthy(text: str) -> bool:
            return text.lower() in ("1", "true", "yes", "on")

        cfg = cls()
        cfg.label = get("FW_LABEL", "dockfence")
        cfg.mode = get("FW_MODE", "enforcing").lower()
        if cfg.mode not in MODES:
            raise ConfigError(f"FW_MODE must be one of {MODES}, got {cfg.mode!r}")
        cfg.listen = get("FW_LISTEN", "127.0.0.1:8420")
        cfg.filter_host = truthy(get("FW_FILTER_HOST", "true"))
        cfg.log_group = int(get("FW_LOG_GROUP", "5"))
        if not 1 <= cfg.log_group <= 65535:
            raise ConfigError("FW_LOG_GROUP must be 1..65535")
        cfg.reconcile = parse_duration(get("FW_RECONCILE", "30s"))
        cfg.log_rate, cfg.log_rate_unit, cfg.log_burst = parse_log_limit(
            get("FW_LOG_LIMIT", "10/second")
        )
        # retention: by age (days) and/or by size (max log rows); either may be 0 = off
        retention = get("FW_RETENTION", "")  # accepted alias, e.g. '30d'
        cfg.retention_days = int(get("FW_RETENTION_DAYS", "0") or "0")
        if retention:
            m = re.fullmatch(r"(\d+)d", retention)
            if m:
                cfg.retention_days = int(m.group(1))
        if cfg.retention_days == 0:
            cfg.retention_days = 30
        cfg.retention_max_rows = int(get("FW_RETENTION_MAX_ROWS", "500000") or "0")
        cfg.event_retention_days = int(get("FW_EVENT_RETENTION_DAYS", "7") or "0") or 7
        cfg.ipv6 = truthy(get("FW_IPV6", "false"))
        cfg.token = get("FW_TOKEN", "")
        cfg.docker_socket = get("FW_DOCKER_SOCKET", "/var/run/docker.sock")
        cfg.db_path = get("FW_DB", "/var/lib/dockfence/dockfence.db")
        cfg.table = get("FW_TABLE", "dockfence")
        cfg.nft_binary = get("FW_NFT_BINARY", "nft")

        # The UI/API token: never allow an empty auth token.
        if not cfg.token:
            cfg.token = secrets.token_hex(16)
            cfg.token_generated = True

        # TLS for the WebUI/API: PEM cert + key files (both or neither).
        # Optional — the default is plain HTTP on localhost, meant to sit
        # behind an SSH tunnel.
        cfg.tls_cert = get("FW_TLS_CERT", "")
        cfg.tls_key = get("FW_TLS_KEY", "")
        if bool(cfg.tls_cert) != bool(cfg.tls_key):
            raise ConfigError("FW_TLS_CERT and FW_TLS_KEY must be set together")
        return cfg

    @property
    def dns_group(self) -> int:
        """NFLOG group for DNS answer capture (packet logs use log_group)."""
        return self.log_group + 1

    @property
    def tls(self) -> tuple[str, str] | None:
        """(cert, key) paths when HTTPS serving is configured, else None."""
        return (self.tls_cert, self.tls_key) if self.tls_cert and self.tls_key else None

    @property
    def bind_host(self) -> str:
        host, _, port = self.listen.rpartition(":")
        return host or "127.0.0.1"

    @property
    def bind_port(self) -> int:
        return int(self.listen.rpartition(":")[2] or "8420")
