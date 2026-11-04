import pytest

from dockfence.config import Config, parse_duration, parse_log_limit


def test_duration():
    assert parse_duration("30s") == 30.0
    assert parse_duration("5m") == 300.0
    assert parse_duration("1000ms") == 1.0
    assert parse_duration("45") == 45.0
    with pytest.raises(Exception):
        parse_duration("soon")


def test_log_limit():
    assert parse_log_limit("10/second") == (10, "second", 20)
    assert parse_log_limit("5/minute") == (5, "minute", 10)
    with pytest.raises(Exception):
        parse_log_limit("10/s")


def test_from_env_defaults():
    cfg = Config.from_env({"FW_TOKEN": "x"})
    assert cfg.mode == "enforcing"
    assert cfg.listen == "127.0.0.1:8420"
    assert cfg.ipv6 is False
    assert cfg.retention_days == 30
    assert cfg.retention_max_rows == 500_000


def test_from_env_full():
    cfg = Config.from_env({
        "FW_MODE": "monitor",
        "FW_IPV6": "true",
        "FW_LISTEN": "0.0.0.0:9000",
        "FW_RETENTION_DAYS": "7",
        "FW_RETENTION_MAX_ROWS": "1000",
        "FW_LOG_LIMIT": "3/minute",
        "FW_TOKEN": "secret",
    })
    assert cfg.mode == "monitor"
    assert cfg.ipv6 is True
    assert cfg.bind_host == "0.0.0.0" and cfg.bind_port == 9000
    assert cfg.retention_days == 7 and cfg.retention_max_rows == 1000
    assert (cfg.log_rate, cfg.log_burst) == (3, 6)


def test_invalid_mode_rejected():
    with pytest.raises(Exception):
        Config.from_env({"FW_MODE": "chaos", "FW_TOKEN": "x"})


def test_token_generated_when_empty():
    cfg = Config.from_env({})
    assert len(cfg.token) == 32
    cfg2 = Config.from_env({})
    assert cfg2.token != cfg.token


def test_tls_options():
    cfg = Config.from_env({
        "FW_TOKEN": "x",
        "FW_TLS_CERT": "/certs/fw.crt",
        "FW_TLS_KEY": "/certs/fw.key",
    })
    assert cfg.tls == ("/certs/fw.crt", "/certs/fw.key")


def test_tls_default_off():
    cfg = Config.from_env({"FW_TOKEN": "x"})
    assert cfg.tls is None
    assert cfg.tls_cert == "" and cfg.tls_key == ""


def test_tls_cert_without_key_rejected():
    with pytest.raises(Exception):
        Config.from_env({"FW_TOKEN": "x", "FW_TLS_CERT": "/certs/fw.crt"})
    with pytest.raises(Exception):
        Config.from_env({"FW_TOKEN": "x", "FW_TLS_KEY": "/certs/fw.key"})
