"""dockfence entrypoint: wires watcher → controller → nft applier,
nflog consumer, retention worker and the API/WebUI.

Runs as a container with: network_mode host, CAP_NET_ADMIN,
docker.sock mounted read-only."""

from __future__ import annotations

import os
import signal
import sys
import threading

from .api import create_app
from .config import Config, ConfigError
from .controller import Controller
from .nflog import EventBus, NFLogConsumer
from .nft import NftApplier
from .retention import RetentionWorker
from .store import Store
from .watcher import DockerWatcher


def _log(msg: str) -> None:
    print(f"[dockfence] {msg}", flush=True)


def main() -> int:
    try:
        cfg = Config.from_env()
    except ConfigError as exc:
        _log(f"config error: {exc}")
        return 2

    # DB is the source of truth: corruption refuses to apply anything
    os.makedirs(os.path.dirname(cfg.db_path), exist_ok=True)
    store = Store(cfg.db_path)

    applier = NftApplier(cfg)
    watcher = DockerWatcher(cfg)
    bus = EventBus()
    controller = Controller(cfg, store, applier, watcher)
    nflog = NFLogConsumer(cfg, store, bus)
    # DNS answer capture learning a NEW ip for a hostname referenced by an
    # enabled dns-rule re-applies the table (kernel set picks up the IP)
    nflog.on_dns_change = controller.rules_changed
    retention = RetentionWorker(cfg, store)

    _log(f"mode={cfg.mode} ipv6={cfg.ipv6} label={cfg.label!r} table=inet/{cfg.table}")
    _log(f"listen={cfg.listen} db={cfg.db_path} nflog_group={cfg.log_group}")
    if cfg.token:
        _log(f"UI/API token: {cfg.token}")

    # docker unreachable at startup must not kill us: reconcile loop retries
    controller.resync(reason="startup")

    threads = [
        threading.Thread(target=watcher.run, args=(controller.handle_event,), daemon=True,
                         name="docker-events"),
        threading.Thread(target=controller.run_reconcile, daemon=True, name="reconcile"),
        threading.Thread(target=nflog.run, daemon=True, name="nflog"),
        threading.Thread(target=nflog.run_dns_rules, daemon=True, name="dns-rules"),
        threading.Thread(target=retention.run, daemon=True, name="retention"),
    ]
    for t in threads:
        t.start()

    app = create_app(cfg, store, controller, watcher, nflog, bus, retention)

    def shutdown(_sig, _frame):
        _log("shutting down…")
        watcher.stop()
        controller.stop()
        nflog.close()
        os._exit(0)

    signal.signal(signal.SIGTERM, shutdown)
    signal.signal(signal.SIGINT, shutdown)

    run_kwargs: dict = dict(host=cfg.bind_host, port=cfg.bind_port, threaded=True,
                            use_reloader=False)
    if cfg.tls:
        run_kwargs["ssl_context"] = cfg.tls  # (cert, key) — serve HTTPS
    _log(f"API+UI listening on {'https' if cfg.tls else 'http'}://{cfg.listen}")
    app.run(**run_kwargs)
    return 0


if __name__ == "__main__":
    sys.exit(main())
