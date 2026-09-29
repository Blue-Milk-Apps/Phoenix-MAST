"""iOS plist binary scanner adapter for saving plist files."""

from __future__ import annotations

import json
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
        extracted = config.extracted_binary if isinstance(config.extracted_binary, ExtractedIPA) else None
        owns_extraction = extracted is None
        target_path = self._resolve_ipa_path(config.project_path) if extracted is None else None
        if extracted is None and target_path is None:
            return [
                ScanResult(
                    scanner_name=self.name,
                    scan_type=self.scan_type,
                    success=False,
                    skipped=True,
                    error_message="No IPA files found in the target project.",
                )
            ]

        try:
            if extracted is None:
                extracted = extract_ipa(target_path)
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

            results = PlistReportBuilder(
                scanner_name=self.name,
                scan_type=self.scan_type,
                description=self.description,
                base_path=extracted.app_bundle,
                output_format=self._output_format,
            ).build(plist_files)
            for result in results:
                if result.relative_target_path == "scan_index.json":
                    index = json.loads(result.raw_output)
                    index["embedded_paths"] = sorted(
                        path.relative_to(extracted.app_bundle).as_posix()
                        for path in extracted.app_bundle.rglob("*")
                        if not path.is_symlink()
                        and (
                            (path.is_dir() and path.suffix in {".bundle", ".framework"})
                            or (path.is_file() and path.suffix == ".dylib")
                        )
                    )
                    result.raw_output = json.dumps(index, indent=2, sort_keys=True)
            return results
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
            if owns_extraction and extracted:
                extracted.cleanup()

    def _resolve_ipa_path(self, project_path: Path) -> Path | None:
        if project_path.is_file():
            if project_path.suffix.lower() == ".apk":
                return None
            return project_path if is_ipa_file(project_path) else None

        return find_ipa_in_directory(project_path)

    def _collect_plist_files(self, app_bundle: Path) -> list[Path]:
        return sorted(path for path in app_bundle.rglob("*") if path.is_file() and path.suffix.lower() == ".plist")

    @staticmethod
    def _normalize_output_format(output_format: str) -> str:
        normalized = output_format.strip().lower()
        if normalized not in {"json", "xml"}:
            raise ValueError("output_format must be 'json' or 'xml'")
        return normalized
