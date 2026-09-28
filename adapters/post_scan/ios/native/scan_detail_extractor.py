"""Native iOS source detail extractor for post-scan processing."""

from __future__ import annotations

from dataclasses import asdict
from typing import Any

from domain.post_scan.dependencies import syft_packages
from domain.post_scan.ios.common.permissions import IOSPermissions
from domain.post_scan.ios.native.app_info import NativeIOSAppInfo
from domain.post_scan.ios.native.file_info import NativeIOSFileInfo
from domain.post_scan.ios.native.meta import NativeIOSMeta
from domain.post_scan.ios.native.scan_extraction_context import NativeIOSScanExtractionContext
from domain.post_scan.ios.native.url_schemes import NativeIOSURLSchemes
from domain.post_scan.rule_assessment import RuleFunctionality, assessments_from_outputs
from domain.post_scan.utilities import secret_values
from ports.post_scan.scan_detail_extractor_port import ScanDetailExtractorPort


class NativeIOSScanDetailExtractor(ScanDetailExtractorPort):
    """Assemble native iOS report sections from source-only evidence models."""

    def extract_sections(self, loaded_outputs: dict[str, Any]) -> dict[str, Any]:
        context = NativeIOSScanExtractionContext(loaded_outputs)

        sections = {
            "meta": asdict(NativeIOSMeta(context)),
            "file_info": asdict(NativeIOSFileInfo(context)),
            "app_info": asdict(NativeIOSAppInfo(context)),
            "url_schemes": NativeIOSURLSchemes(context).items,
            "functionality": RuleFunctionality(
                loaded_outputs.get("opengrep"), assessments=assessments_from_outputs(loaded_outputs)
            ).items,
            "third_party_sdks": sorted({p["name"] for p in syft_packages(loaded_outputs)}),
            "permissions": IOSPermissions(loaded_outputs).items,
            "hardcoded_values": secret_values(loaded_outputs),
            "endpoints": [],
        }
        return sections
