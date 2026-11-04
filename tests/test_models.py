import pytest

from dockfence.models import ValidationError, validate_rule


def test_valid_rule_plan_example():
    fields = validate_rule({"direction": "out", "proto": "tcp", "port": 443,
                            "cidr": "203.0.113.4/32", "action": "accept", "enabled": True})
    assert fields["cidr"] == "203.0.113.4/32"
    assert fields["cidr_family"] == 4


def test_defaults():
    fields = validate_rule({})
    assert fields["direction"] == "out"
    assert fields["proto"] == "any"
    assert fields["action"] == "accept"
    assert fields["cidr"] == ""
    assert fields["enabled"] is True


def test_port_range():
    fields = validate_rule({"proto": "tcp", "port": 1000, "port_end": 1010})
    assert fields["port_end"] == 1010


def test_proto_requires_port():
    with pytest.raises(ValidationError):
        validate_rule({"proto": "tcp"})


def test_any_proto_with_port_is_allowed():
    """'any' + dport matches both tcp and udp (renderer emits th dport)."""
    fields = validate_rule({"direction": "out", "proto": "any", "port": 53})
    assert fields["port"] == 53
    fields = validate_rule({"direction": "out", "proto": "any", "port": 1000, "port_end": 2000})
    assert (fields["port"], fields["port_end"]) == (1000, 2000)


def test_icmp_still_rejects_port():
    with pytest.raises(ValidationError):
        validate_rule({"proto": "icmp", "port": 53})


def test_port_end_requires_port():
    with pytest.raises(ValidationError):
        validate_rule({"proto": "tcp", "port_end": 90})


def test_position_passthrough():
    fields = validate_rule({"direction": "out", "proto": "any", "action": "drop", "position": -3})
    assert fields["position"] == -3
    with pytest.raises(ValidationError):
        validate_rule({"direction": "out", "proto": "any", "action": "drop", "position": "x"})


def test_port_end_before_port():
    with pytest.raises(ValidationError):
        validate_rule({"proto": "tcp", "port": 100, "port_end": 90})


def test_bad_cidr():
    with pytest.raises(ValidationError):
        validate_rule({"proto": "any", "cidr": "not-a-cidr"})


def test_v6_cidr():
    fields = validate_rule({"direction": "in", "cidr": "fd00::/8"})
    assert fields["cidr_family"] == 6


def test_partial_patch_keeps_unknown():
    fields = validate_rule({"enabled": False}, partial=True)
    assert fields == {"enabled": False}
    fields = validate_rule({"port": 8}, partial=True)
    assert fields == {"port": 8}


def test_dns_name_normalization():
    fields = validate_rule({"proto": "tcp", "port": 443, "dns": " Example.COM. "})
    assert fields["dns"] == "example.com"


def test_dns_requires_fqdn():
    for bad in ("localhost", "-bad.example.com", "a..b.com", "exa mple.com", "a" * 250 + ".com"):
        with pytest.raises(ValidationError):
            validate_rule({"proto": "tcp", "port": 443, "dns": bad})


def test_dns_and_cidr_mutually_exclusive():
    with pytest.raises(ValidationError):
        validate_rule({"proto": "tcp", "port": 443, "cidr": "203.0.113.4/32",
                       "dns": "example.com", "action": "accept"})


def test_dns_with_any_proto_and_no_port_is_fine():
    fields = validate_rule({"proto": "any", "dns": "example.com", "action": "drop"})
    assert fields["dns"] == "example.com" and fields["port"] is None
