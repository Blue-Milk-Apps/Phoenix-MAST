"""Post-scan processing helpers for assembling report-ready output."""

from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Any

from ports.scan_detail_extractor_port import ScanDetailExtractorPort
from ports.scan_output_loader_port import ScanOutputLoaderPort


class PostScanProcessingService:
    """Assemble report sections from persisted scan outputs."""

    DEFAULT_REVIEWER_ORG = "AppCritIQ Security Report"

    def __init__(
        self,
        scan_output_loader: ScanOutputLoaderPort,
        scan_detail_extractor: ScanDetailExtractorPort,
    ) -> None:
        self._scan_output_loader = scan_output_loader
        self._scan_detail_extractor = scan_detail_extractor

    def process(self, scan_output_path: Path) -> dict[str, Any]:
        """Build the first post-scan output shape, starting with the meta section."""

        loaded_outputs = self._scan_output_loader.load(scan_output_path)
        other_sections = self._scan_detail_extractor.extract_sections(loaded_outputs)
        return {
            "meta": self._build_meta(loaded_outputs),
            **other_sections,
        }

    def _build_meta(self, loaded_outputs: dict[str, Any]) -> dict[str, str]:
        scan_metadata = loaded_outputs.get("scan_metadata") or {}
        androguard_metadata = loaded_outputs.get("androguard_metadata") or {}
        aapt2_identity = loaded_outputs.get("aapt2_identity") or {}
        app_display_name = self._first_non_empty(
            androguard_metadata.get("app_name"),
            aapt2_identity.get("application_label"),
        )
        file_name = self._first_non_empty(
            androguard_metadata.get("file_name"),
            Path(scan_metadata.get("project_path", "")).name,
        )
        package_name = self._first_non_empty(
            androguard_metadata.get("package"),
            aapt2_identity.get("package_name"),
        )
        version_name = self._first_non_empty(
            androguard_metadata.get("version_name"),
            aapt2_identity.get("version_name"),
        )
        version_code = self._first_non_empty(
            androguard_metadata.get("version_code"),
            aapt2_identity.get("version_code"),
        )
        platform = self._normalize_platform(scan_metadata.get("platform"))

        return {
            "app_display_name": app_display_name,
            "file_name": file_name,
            "package_name": package_name,
            "scan_date": self._derive_scan_date(scan_metadata, Path(loaded_outputs["scan_output_path"])),
            "platform": platform,
            "version_name": version_name,
            "version_code": version_code,
            "reviewer_org": self.DEFAULT_REVIEWER_ORG,
        }

    @staticmethod
    def _first_non_empty(*values: object) -> str:
        for value in values:
            if value is None:
                continue
            text = str(value).strip()
            if text:
                return text
        return ""

    @staticmethod
    def _normalize_platform(platform: object) -> str:
        text = str(platform or "").strip()
        if not text:
            return ""
        if text.upper() == "ANDROID":
            return "Android"
        if text.upper() == "IOS":
            return "iOS"
        return text

    @staticmethod
    def _derive_scan_date(scan_metadata: dict[str, Any], scan_output_path: Path) -> str:
        explicit = str(scan_metadata.get("scan_date", "")).strip()
        if explicit:
            return explicit

        try:
            timestamp = scan_output_path.name.rsplit("_", 2)[-2:]
            parsed = datetime.strptime("_".join(timestamp), "%Y-%m-%d_%H-%M-%S")
            return parsed.strftime("%Y-%m-%d %H:%M:%S")
        except (ValueError, IndexError):
            return ""
