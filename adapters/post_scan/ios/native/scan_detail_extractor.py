"""Native iOS source detail extractor for post-scan processing."""

from __future__ import annotations

from dataclasses import asdict
from typing import Any

from domain.post_scan.ios.common.data_storage_evidence import IOSDataStorageEvidence
from domain.post_scan.ios.common.functionality import IOSFunctionality
from domain.post_scan.ios.common.network_evidence import IOSNetworkEvidence
from domain.post_scan.ios.common.permissions import IOSPermissions
from domain.post_scan.ios.common.third_party_sdks import IOSThirdPartySDKs
from domain.post_scan.ios.native.app_info import NativeIOSAppInfo
from domain.post_scan.ios.native.code_evidence import NativeIOSCodeEvidence
from domain.post_scan.ios.native.file_info import NativeIOSFileInfo
from domain.post_scan.ios.native.meta import NativeIOSMeta
from domain.post_scan.ios.native.scan_extraction_context import NativeIOSScanExtractionContext
from domain.post_scan.ios.native.url_schemes import NativeIOSURLSchemes
from ports.post_scan.scan_detail_extractor_port import ScanDetailExtractorPort


class NativeIOSScanDetailExtractor(ScanDetailExtractorPort):
    """Assemble native iOS report sections from source-only evidence models."""

    def extract_sections(self, loaded_outputs: dict[str, Any]) -> dict[str, Any]:
        context = NativeIOSScanExtractionContext(loaded_outputs)
        functionality = asdict(IOSFunctionality(loaded_outputs))
        third_party_sdks = asdict(IOSThirdPartySDKs(loaded_outputs))

        return {
            "meta": asdict(NativeIOSMeta(context)),
            "file_info": asdict(NativeIOSFileInfo(context)),
            "app_info": asdict(NativeIOSAppInfo(context)),
            "url_schemes": NativeIOSURLSchemes(context).items,
            "functionality": {key.replace("_", " "): value for key, value in functionality.items()},
            "third_party_sdks": {key.replace("_", " "): value for key, value in third_party_sdks.items()},
            "permissions": IOSPermissions(loaded_outputs).items,
            "code_evidence": asdict(NativeIOSCodeEvidence(context)),
            "network_evidence": asdict(IOSNetworkEvidence(loaded_outputs)),
            "data_storage_evidence": asdict(IOSDataStorageEvidence(loaded_outputs)),
            "hardcoded_values": {"urls": [], "emails": [], "secrets": []},
            "endpoints": [],
        }
