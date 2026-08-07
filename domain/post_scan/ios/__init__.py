"""iOS post-scan builders."""

from domain.post_scan.ios.app_info import IOSAppInfo
from domain.post_scan.ios.code_evidence import IOSCodeEvidence
from domain.post_scan.ios.data_storage_evidence import IOSDataStorageEvidence
from domain.post_scan.ios.endpoints import IOSEndpoints
from domain.post_scan.ios.file_info import IOSFileInfo
from domain.post_scan.ios.functionality import IOSFunctionality
from domain.post_scan.ios.hardcoded_values import IOSHardcodedValues
from domain.post_scan.ios.ipa_binary_evidence import IOSIPABinaryEvidence
from domain.post_scan.ios.meta import IOSMeta
from domain.post_scan.ios.network_evidence import IOSNetworkEvidence
from domain.post_scan.ios.permissions import IOSPermissions
from domain.post_scan.ios.resilience_evidence import IOSResilienceEvidence
from domain.post_scan.ios.third_party_sdks import IOSThirdPartySDKs
from domain.post_scan.ios.url_schemes import IOSURLSchemes

__all__ = [
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
]
