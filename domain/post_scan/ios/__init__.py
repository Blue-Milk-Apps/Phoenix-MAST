"""iOS post-scan domain models."""

from domain.post_scan.ios.binary import (
    IOSAppInfo,
    IOSEndpoints,
    IOSFileInfo,
    IOSIPABinaryEvidence,
    IOSMeta,
    IOSURLSchemes,
)
from domain.post_scan.ios.common import (
    EvidenceEntry,
    IOSPermissions,
)
from domain.post_scan.ios.native import (
    NativeIOSAppInfo,
    NativeIOSFileInfo,
    NativeIOSMeta,
    NativeIOSScanExtractionContext,
    NativeIOSURLSchemes,
)

__all__ = [
    "EvidenceEntry",
    "IOSAppInfo",
    "IOSEndpoints",
    "IOSFileInfo",
    "IOSIPABinaryEvidence",
    "IOSMeta",
    "IOSPermissions",
    "IOSURLSchemes",
    "NativeIOSAppInfo",
    "NativeIOSFileInfo",
    "NativeIOSMeta",
    "NativeIOSScanExtractionContext",
    "NativeIOSURLSchemes",
]
