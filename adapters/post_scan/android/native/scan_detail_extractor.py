"""Native Android source detail extractor for post-scan processing."""

from __future__ import annotations

from typing import Any

from ports.post_scan.scan_detail_extractor_port import ScanDetailExtractorPort


class NativeAndroidScanDetailExtractor(ScanDetailExtractorPort):
    """Placeholder for native Android source post-scan extraction."""

    def extract_sections(self, loaded_outputs: dict[str, Any]) -> dict[str, Any]:
        return {}
