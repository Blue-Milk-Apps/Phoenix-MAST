"""Flutter source detail extractor for post-scan processing."""

from __future__ import annotations

from dataclasses import asdict
from typing import Any

from domain.post_scan.flutter import (
    FlutterAppInfo,
    FlutterDependencyInventory,
    FlutterFileInfo,
    FlutterMeta,
    FlutterPlatformInventory,
    FlutterScanExtractionContext,
)
from ports.post_scan.scan_detail_extractor_port import ScanDetailExtractorPort


class FlutterScanDetailExtractor(ScanDetailExtractorPort):
    """Assemble Flutter source metadata and inventory report sections."""

    def extract_sections(self, loaded_outputs: dict[str, Any]) -> dict[str, Any]:
        context = FlutterScanExtractionContext(loaded_outputs)
        return {
            "meta": asdict(FlutterMeta(context)),
            "file_info": asdict(FlutterFileInfo(context)),
            "app_info": asdict(FlutterAppInfo(context)),
            "platform_inventory": asdict(FlutterPlatformInventory(context)),
            "dependency_inventory": asdict(FlutterDependencyInventory(context)),
        }
