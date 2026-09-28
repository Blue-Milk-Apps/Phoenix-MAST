"""Domain models shared by iOS binary and native source post-scan processing."""

from domain.post_scan.ios.common.evidence import EvidenceEntry
from domain.post_scan.ios.common.permissions import IOSPermissions

__all__ = [
    "EvidenceEntry",
    "IOSPermissions",
]
