
import pytest

from src.security.ip_validator import IPAccessController


def test_valid_ipv4_without_allowlist():
    controller = IPAccessController()

    result = controller.validate_ip("192.168.1.10")

    assert result.allowed is True
    assert result.reason == "IP_ALLOWED"


def test_valid_ipv6_without_allowlist():
    controller = IPAccessController()

    result = controller.validate_ip("2001:db8::1")

    assert result.allowed is True


def test_corporate_cidr_allows_matching_ip():
    controller = IPAccessController(
        allowed_networks=["10.10.0.0/16"]
    )

    result = controller.validate_ip("10.10.5.20")

    assert result.allowed is True
    assert result.reason == "IP_ALLOWED"


def test_corporate_cidr_blocks_non_matching_ip():
    controller = IPAccessController(
        allowed_networks=["10.10.0.0/16"]
    )

    result = controller.validate_ip("192.168.1.10")

    assert result.allowed is False
    assert result.reason == "IP_NOT_IN_ALLOWED_CIDR"


def test_blacklisted_ip_is_blocked():
    controller = IPAccessController(
        blocked_ips=["192.168.1.100"]
    )

    result = controller.validate_ip("192.168.1.100")

    assert result.allowed is False
    assert result.reason == "BLACKLISTED_IP"


def test_blacklist_takes_priority_over_allowlist():
    controller = IPAccessController(
        allowed_networks=["10.10.0.0/16"],
        blocked_ips=["10.10.5.20"],
    )

    result = controller.validate_ip("10.10.5.20")

    assert result.allowed is False
    assert result.reason == "BLACKLISTED_IP"


def test_invalid_ip_is_rejected():
    controller = IPAccessController()

    result = controller.validate_ip("999.999.999.999")

    assert result.allowed is False
    assert result.reason == "INVALID_IP_ADDRESS"


def test_ipv6_does_not_match_ipv4_network():
    controller = IPAccessController(
        allowed_networks=["10.10.0.0/16"]
    )

    result = controller.validate_ip("2001:db8::1")

    assert result.allowed is False
    assert result.reason == "IP_NOT_IN_ALLOWED_CIDR"


def test_invalid_cidr_configuration_raises_error():
    with pytest.raises(ValueError):
        IPAccessController(
            allowed_networks=["invalid-cidr"]
        )
