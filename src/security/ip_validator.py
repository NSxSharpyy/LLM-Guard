
import ipaddress
from dataclasses import dataclass, field
from typing import Iterable


@dataclass(frozen=True)
class IPValidationResult:
    allowed: bool
    client_ip: str
    reason: str


@dataclass
class IPAccessController:
    """
    Validates client IP addresses against corporate VPN CIDR
    allowlists and malicious IP denylists.
    """

    allowed_networks: Iterable[str] = field(default_factory=tuple)
    blocked_ips: Iterable[str] = field(default_factory=tuple)

    def __post_init__(self) -> None:
        self._networks = tuple(
            ipaddress.ip_network(network, strict=False)
            for network in self.allowed_networks
        )
        self._blocked = frozenset(
            ipaddress.ip_address(address)
            for address in self.blocked_ips
        )

    def validate_ip(self, client_ip: str) -> IPValidationResult:
        """Validate an IP address and apply blacklist/allowlist rules."""

        try:
            address = ipaddress.ip_address(client_ip.strip())
        except (ValueError, AttributeError):
            return IPValidationResult(
                allowed=False,
                client_ip=str(client_ip),
                reason="INVALID_IP_ADDRESS",
            )

        if address in self._blocked:
            return IPValidationResult(
                allowed=False,
                client_ip=str(address),
                reason="BLACKLISTED_IP",
            )

        if self._networks:
            matching_network = any(
                address.version == network.version
                and address in network
                for network in self._networks
            )

            if not matching_network:
                return IPValidationResult(
                    allowed=False,
                    client_ip=str(address),
                    reason="IP_NOT_IN_ALLOWED_CIDR",
                )

        return IPValidationResult(
            allowed=True,
            client_ip=str(address),
            reason="IP_ALLOWED",
        )
