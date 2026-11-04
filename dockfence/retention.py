"""Retention worker: prune logs by age AND by max row count (configurable
independently; FW_RETENTION_DAYS / FW_RETENTION_MAX_ROWS), events by age."""

from __future__ import annotations

import threading

SWEEP_SECONDS = 600


class RetentionWorker:
    def __init__(self, cfg, store):
        self.cfg = cfg
        self.store = store
        self._stop = threading.Event()
        self.last_stats: dict | None = None

    def run(self) -> None:
        while not self._stop.is_set():
            if self._stop.wait(timeout=SWEEP_SECONDS):
                break
            try:
                self.sweep()
            except Exception:  # noqa: BLE001 — never kill the worker
                self.last_stats = None

    def sweep(self) -> dict:
        stats = self.store.prune_retention(
            days=self.cfg.retention_days,
            max_rows=self.cfg.retention_max_rows,
            event_days=self.cfg.event_retention_days,
        )
        self.last_stats = stats
        return stats

    def stop(self) -> None:
        self._stop.set()
