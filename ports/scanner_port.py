"""Scanner port - abstract interface for all scanners."""

from abc import ABC, abstractmethod

from domain.models import ScanConfig, ScanResult, ScanType


class ScannerPort(ABC):
    """Abstract base class for security scanners."""

    @property
    @abstractmethod
    def scan_type(self) -> ScanType:
        """Return the type of scan this scanner performs."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Return human-readable scanner name."""

    @property
    def description(self) -> str:
        """Return a short description of what this scanner checks for."""
        return ""

    @abstractmethod
    def scan(self, config: ScanConfig) -> list[ScanResult]:
        """Execute the scan and return results.

        Args:
            config: Scan configuration containing paths and options.

        Returns:
            List of ScanResult objects containing scanner execution metadata.
        """

    @staticmethod
    def format_stdout_prefix(name) -> str:
        """Used to pretty-print stdout from commands"""
        name = ScannerPort.format_strip_scan_type(name)
        return f"{name} -> "

    @staticmethod
    def format_strip_scan_type(name) -> str:
        return str(name).replace(ScanType.__name__ + ".", "").replace("_", " ").title()

    @abstractmethod
    def is_available(self) -> bool:
        """Check if the scanner tool is available on the system."""
