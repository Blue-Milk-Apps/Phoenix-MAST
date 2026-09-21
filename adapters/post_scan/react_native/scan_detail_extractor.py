"""Assemble report-ready React Native source sections."""

from __future__ import annotations

from typing import Any

from domain.post_scan.react_native.report_models import build_report_sections
from domain.post_scan.react_native.scan_extraction_context import ReactNativeScanExtractionContext
from ports.post_scan.scan_detail_extractor_port import ScanDetailExtractorPort


class ReactNativeScanDetailExtractor(ScanDetailExtractorPort):
    def extract_sections(self, loaded_outputs: dict[str, Any]) -> dict[str, Any]:
        return build_report_sections(ReactNativeScanExtractionContext(loaded_outputs))
