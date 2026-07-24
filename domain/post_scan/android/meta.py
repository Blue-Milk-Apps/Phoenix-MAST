"""Build Android binary meta section for post-scan reports."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

from domain.post_scan.utilities import first_non_empty


@dataclass
class AndroidMeta:
    app_display_name: str
    file_name: str
    package_name: str
    scan_date: str
    platform: str
    version_name: str
    version_code: str
    reviewer_org: str

    DEFAULT_REVIEWER_ORG = "Phoenix Security Report"

    def __init__(self, loaded_outputs: dict[str, Any]) -> None:
        scan_metadata = loaded_outputs.get("scan_metadata") or {}
        androguard_metadata = loaded_outputs.get("androguard_metadata") or {}
        aapt2_identity = loaded_outputs.get("aapt2_identity") or {}
        scan_output_path = Path(str(loaded_outputs.get("scan_output_path", "")))

        self.app_display_name = first_non_empty(
            androguard_metadata.get("app_name"),
            aapt2_identity.get("application_label"),
        )
        self.file_name = first_non_empty(
            androguard_metadata.get("file_name"),
            Path(scan_metadata.get("project_path", "")).name,
        )
        self.package_name = first_non_empty(
            androguard_metadata.get("package"),
            aapt2_identity.get("package_name"),
        )
        self.scan_date = self._derive_scan_date(scan_metadata, scan_output_path)
        self.platform = self._normalize_platform(scan_metadata.get("platform"))
        self.version_name = first_non_empty(
            androguard_metadata.get("version_name"),
            aapt2_identity.get("version_name"),
        )
        self.version_code = first_non_empty(
            androguard_metadata.get("version_code"),
            aapt2_identity.get("version_code"),
        )
        self.reviewer_org = self.DEFAULT_REVIEWER_ORG

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
