"""iOS post-scan domain models."""

from domain.post_scan.ios.binary import (
    IOSAppInfo,
    IOSCodeEvidence,
    IOSEndpoints,
    IOSFileInfo,
    IOSHardcodedValues,
    IOSIPABinaryEvidence,
    IOSMeta,
    IOSResilienceEvidence,
    IOSURLSchemes,
)
from domain.post_scan.ios.common import (
    EvidenceEntry,
    IOSDataStorageEvidence,
    IOSFunctionality,
    IOSNetworkEvidence,
    IOSPermissions,
    IOSThirdPartySDKs,
)
from domain.post_scan.ios.native import (
    NativeIOSAppInfo,
    NativeIOSCodeEvidence,
    NativeIOSFileInfo,
    NativeIOSMeta,
    NativeIOSScanExtractionContext,
    NativeIOSURLSchemes,
)

__all__ = [
    "EvidenceEntry",
    "IOSAppInfo",
    "IOSCodeEvidence",
    "IOSDataStorageEvidence",
    "IOSEndpoints",
    "IOSFileInfo",
    "IOSFunctionality",
    "IOSHardcodedValues",
    "IOSIPABinaryEvidence",
    "IOSMeta",
    "IOSNetworkEvidence",
    "IOSPermissions",
    "IOSResilienceEvidence",
    "IOSThirdPartySDKs",
    "IOSURLSchemes",
    "NativeIOSAppInfo",
    "NativeIOSCodeEvidence",
    "NativeIOSFileInfo",
    "NativeIOSMeta",
    "NativeIOSScanExtractionContext",
    "NativeIOSURLSchemes",
]
