"""Native Android source detail extractor for post-scan processing."""

from __future__ import annotations

from dataclasses import asdict
from typing import Any

from domain.post_scan.android.native import (
    NativeAndroidAppComponents,
    NativeAndroidAppInfo,
    NativeAndroidApplication,
    NativeAndroidDeepLinks,
    NativeAndroidEndpoints,
    NativeAndroidFileInfo,
    NativeAndroidFunctionality,
    NativeAndroidHardcodedValues,
    NativeAndroidMeta,
    NativeAndroidPermissions,
    NativeAndroidScanExtractionContext,
)
from ports.post_scan.scan_detail_extractor_port import ScanDetailExtractorPort


class NativeAndroidScanDetailExtractor(ScanDetailExtractorPort):
    """Assemble native Android source metadata report sections."""

    def extract_sections(self, loaded_outputs: dict[str, Any]) -> dict[str, Any]:
        context = NativeAndroidScanExtractionContext(loaded_outputs)
        sections = {
            "meta": asdict(NativeAndroidMeta(context)),
            "file_info": asdict(NativeAndroidFileInfo(context)),
            "app_info": asdict(NativeAndroidAppInfo(context)),
            "application": asdict(NativeAndroidApplication(context)),
            "app_components": asdict(NativeAndroidAppComponents(context)),
            "permissions": NativeAndroidPermissions(context).items,
            "deep_links": asdict(NativeAndroidDeepLinks(context)),
        }
        functionality = NativeAndroidFunctionality(context)
        if functionality.assessed:
            sections["functionality"] = functionality.items

        hardcoded_values = NativeAndroidHardcodedValues(context)
        if hardcoded_values.assessed:
            sections["hardcoded_values"] = {
                "urls": hardcoded_values.urls,
                "emails": hardcoded_values.emails,
                "secrets": hardcoded_values.secrets,
            }
            sections["endpoints"] = NativeAndroidEndpoints(hardcoded_values).items
        return sections
