"""Plist binary scanner adapter for saving plist files to the output directory."""

from __future__ import annotations

from pathlib import Path

from domain.models import ScanConfig, ScanResult, ScanType
from ports.scanner_port import ScannerPort
from utilities.ipa_utils import (
    ExtractedIPA,
    extract_ipa,
    find_ipa_in_directory,
    is_ipa_file,
)
from utilities.plist_report import PlistReportBuilder


class PlistBinaryScanner(ScannerPort):
    """Scanner for normalizing plist files extracted from IPA binaries."""

    def __init__(self, output_format: str = "json") -> None:
        self._output_format = self._normalize_output_format(output_format)

    @property
    def scan_type(self) -> ScanType:
        return ScanType.PLIST_BINARY

    @property
    def name(self) -> str:
        return "Plist Binary Saver"

    @property
    def description(self) -> str:
        return "Normalized plist files extracted from IPA binaries written to the scan output directory."

    def is_available(self) -> bool:
        return True

    def scan(self, config: ScanConfig) -> list[ScanResult]:
        ipa_path = self._resolve_ipa_path(config.project_path)
        if ipa_path is None:
            return [
                ScanResult(
                    scanner_name=self.name,
                    scan_type=self.scan_type,
                    success=False,
                    skipped=True,
                    error_message="No IPA files found in the target project.",
                )
            ]

        extracted: ExtractedIPA | None = None
        try:
            extracted = extract_ipa(ipa_path)
            plist_files = self._collect_plist_files(extracted.app_bundle)
            if not plist_files:
                return [
                    ScanResult(
                        scanner_name=self.name,
                        scan_type=self.scan_type,
                        success=False,
                        skipped=True,
                        error_message="No plist files found in the IPA.",
                    )
                ]

            return PlistReportBuilder(
                scanner_name=self.name,
                scan_type=self.scan_type,
                description=self.description,
                base_path=extracted.app_bundle,
                output_format=self._output_format,
            ).build(plist_files)
        except Exception as exc:
            return [
                ScanResult(
                    scanner_name=self.name,
                    scan_type=self.scan_type,
                    success=False,
                    error_message=str(exc),
                )
            ]
        finally:
            if extracted:
                extracted.cleanup()

    def _resolve_ipa_path(self, project_path: Path) -> Path | None:
        if project_path.is_file():
            if project_path.suffix.lower() == ".apk":
                return None
            return project_path if is_ipa_file(project_path) else None

        return find_ipa_in_directory(project_path)

    def _collect_plist_files(self, app_bundle: Path) -> list[Path]:
        return sorted(
            path
            for path in app_bundle.rglob("*")
            if path.is_file() and path.suffix.lower() == ".plist"
        )

    @staticmethod
    def _normalize_output_format(output_format: str) -> str:
        normalized = output_format.strip().lower()
        if normalized not in {"json", "xml"}:
            raise ValueError("output_format must be 'json' or 'xml'")
        return normalized
