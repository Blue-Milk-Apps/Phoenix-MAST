"""Post-scan processing helpers for assembling report-ready output."""

from __future__ import annotations

from dataclasses import asdict
from pathlib import Path
from typing import Any

from domain.post_scan.rule_assessment import rule_assessments
from domain.post_scan.utilities import summarize_secret_scans
from ports.post_scan.scan_detail_extractor_port import ScanDetailExtractorPort
from ports.post_scan.scan_output_loader_port import ScanOutputLoaderPort


class PostScanProcessingService:
    """Assemble report sections from persisted scan outputs."""

    DEFAULT_REVIEWER_ORG = "Phoenix Security Report"

    def __init__(
        self,
        scan_output_loader: ScanOutputLoaderPort,
        scan_detail_extractor: ScanDetailExtractorPort,
    ) -> None:
        self._scan_output_loader = scan_output_loader
        self._scan_detail_extractor = scan_detail_extractor

    def process(self, scan_output_path: Path) -> dict[str, Any]:
        """Build report-ready output from persisted scan outputs."""

        scanner_outputs = self._scan_output_loader.load(scan_output_path)
        sections = self._scan_detail_extractor.extract_sections(scanner_outputs)
        sections["rule_assessments"] = rule_assessments(scanner_outputs.get("opengrep"))
        sections["secret_scans"] = [asdict(summary) for summary in summarize_secret_scans(scanner_outputs)]
        return sections
