import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest

from dockfence.config import Config
from dockfence.store import Store


@pytest.fixture
def cfg(tmp_path):
    return Config(
        label="dockfence",
        mode="enforcing",
        listen="127.0.0.1:8420",
        filter_host=True,
        log_group=5,
        reconcile=30.0,
        log_rate=10,
        log_rate_unit="second",
        log_burst=20,
        retention_days=30,
        retention_max_rows=500_000,
        event_retention_days=7,
        ipv6=True,
        token="test-token",
        docker_socket="/var/run/docker.sock",
        db_path=str(tmp_path / "test.db"),
        table="dockfence",
    )


@pytest.fixture
def store(cfg):
    return Store(cfg.db_path)
