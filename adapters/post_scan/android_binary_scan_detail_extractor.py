"""Android binary detail extractor for post-scan processing."""

from __future__ import annotations

from typing import Any

from ports.scan_detail_extractor_port import ScanDetailExtractorPort


class AndroidBinaryScanDetailExtractor(ScanDetailExtractorPort):
    """Extract Android-binary-specific sections from loaded scan outputs."""

    def extract_sections(self, loaded_outputs: dict[str, Any]) -> dict[str, Any]:
        return {}
