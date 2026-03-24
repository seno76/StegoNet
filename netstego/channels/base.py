"""Abstract base class for steganographic channels.

Every channel implementation must inherit from StegoChannel
and implement all abstract methods.
"""

from abc import ABC, abstractmethod

from scapy.packet import Packet


class StegoChannel(ABC):
    """Base class for all steganographic channels."""

    @abstractmethod
    def encode(self, data: bytes, dest_ip: str, **kwargs) -> list[Packet]:
        """Encode data into a list of Scapy packets.

        Args:
            data: Encrypted payload bytes to embed.
            dest_ip: Destination IP address.
            **kwargs: Channel-specific options.

        Returns:
            List of Scapy packets carrying the hidden data.
        """

    @abstractmethod
    def decode(self, packets: list[Packet]) -> bytes:
        """Decode hidden data from a list of packets.

        Args:
            packets: List of captured Scapy packets.

        Returns:
            Extracted payload bytes.
        """

    @property
    @abstractmethod
    def bits_per_packet(self) -> int:
        """Number of data bits embedded per single packet."""

    @property
    @abstractmethod
    def protocol_filter(self) -> str:
        """BPF filter string for the receiver sniffer.

        May contain `{ip}` placeholder for source IP.
        Example: ``'icmp and src host {ip}'``
        """

    @property
    def name(self) -> str:
        """Human-readable channel name."""
        return self.__class__.__name__
