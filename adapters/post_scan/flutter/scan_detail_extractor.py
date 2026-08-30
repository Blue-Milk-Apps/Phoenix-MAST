"""Flutter source detail extractor for post-scan processing."""

from __future__ import annotations

from dataclasses import asdict
from typing import Any

from domain.post_scan.flutter import (
    FlutterAppComponents,
    FlutterAppInfo,
    FlutterApplication,
    FlutterDeepLinks,
    FlutterDependencyInventory,
    FlutterFileInfo,
    FlutterMeta,
    FlutterPermissions,
    FlutterPlatformInventory,
    FlutterScanExtractionContext,
    FlutterURLSchemes,
)
from ports.post_scan.scan_detail_extractor_port import ScanDetailExtractorPort


class FlutterScanDetailExtractor(ScanDetailExtractorPort):
    """Assemble Flutter source metadata and inventory report sections."""

    def extract_sections(self, loaded_outputs: dict[str, Any]) -> dict[str, Any]:
        context = FlutterScanExtractionContext(loaded_outputs)
        url_schemes = FlutterURLSchemes(context)
        return {
            "meta": asdict(FlutterMeta(context)),
            "file_info": asdict(FlutterFileInfo(context)),
            "app_info": asdict(FlutterAppInfo(context)),
            "platform_inventory": asdict(FlutterPlatformInventory(context)),
            "dependency_inventory": asdict(FlutterDependencyInventory(context)),
            "application": asdict(FlutterApplication(context)),
            "app_components": asdict(FlutterAppComponents(context)),
            "permissions": FlutterPermissions(context).items,
            "deep_links": asdict(FlutterDeepLinks(context)),
            "url_schemes": url_schemes.items,
            "queried_url_schemes": url_schemes.queried_schemes,
        }
