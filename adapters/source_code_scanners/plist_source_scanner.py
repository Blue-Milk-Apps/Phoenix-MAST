"""Plist source scanner adapter."""

from __future__ import annotations

import json
from pathlib import Path

from domain.models import ScanConfig, ScanResult, ScanType
from ports.scanner_port import ScannerPort
from utilities.plist_report import PlistReportBuilder


class PlistSourceScanner(ScannerPort):
    """Scanner for normalizing plist files from source trees."""

    def __init__(self, output_format: str = "json") -> None:
        self._output_format = self._normalize_output_format(output_format)

    @property
    def scan_type(self) -> ScanType:
        return ScanType.PLIST_SOURCE

    @property
    def name(self) -> str:
        return "Plist Source Saver"

    @property
    def description(self) -> str:
        return "Normalized plist files from the source tree written to the scan output directory."

    def is_available(self) -> bool:
        return True

    def scan(self, config: ScanConfig) -> list[ScanResult]:
        plist_files = self._collect_plist_files(config.project_path)
        if not plist_files:
            raw_output = json.dumps(
                {
                    "error": "No plist files found in the source project.",
                    "skipped": True,
                },
                indent=2,
                sort_keys=True,
            )
            return [
                ScanResult(
                    scanner_name=self.name,
                    scan_type=self.scan_type,
                    success=False,
                    skipped=True,
                    error_message="No plist files found in the source project.",
                    raw_output=raw_output,
                    relative_target_path="scan_summary.json",
                )
            ]

        return PlistReportBuilder(
            scanner_name=self.name,
            scan_type=self.scan_type,
            description=self.description,
            base_path=config.project_path.parent
            if config.project_path.is_file()
            else config.project_path,
            output_format=self._output_format,
        ).build(plist_files)

    def _collect_plist_files(self, project_path: Path) -> list[Path]:
        if project_path.is_file():
            return [project_path] if project_path.suffix.lower() == ".plist" else []
        return sorted(
            path
            for path in project_path.rglob("*")
            if path.is_file() and path.suffix.lower() == ".plist"
        )

    @staticmethod
    def _normalize_output_format(output_format: str) -> str:
        normalized = output_format.strip().lower()
        if normalized not in {"json", "xml"}:
            raise ValueError("output_format must be 'json' or 'xml'")
        return normalized
