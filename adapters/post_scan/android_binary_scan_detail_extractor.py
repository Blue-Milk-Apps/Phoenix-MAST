"""Android binary detail extractor for post-scan processing."""

from __future__ import annotations

from typing import Any

from ports.scan_detail_extractor_port import ScanDetailExtractorPort


class AndroidBinaryScanDetailExtractor(ScanDetailExtractorPort):
    """Extract Android-binary-specific sections from loaded scan outputs."""

    def extract_sections(self, loaded_outputs: dict[str, Any]) -> dict[str, Any]:
        return {
            "app_info": self._build_app_info(loaded_outputs),
        }

    def _build_app_info(self, loaded_outputs: dict[str, Any]) -> dict[str, str]:
        androguard_metadata = loaded_outputs.get("androguard_metadata") or {}
        aapt2_identity = loaded_outputs.get("aapt2_identity") or {}

        return {
            "icon_path": "",
            "name": self._first_non_empty(
                androguard_metadata.get("app_name"),
                aapt2_identity.get("application_label"),
            ),
            "package_name": self._first_non_empty(
                androguard_metadata.get("package"),
                aapt2_identity.get("package_name"),
            ),
            "main_activity": self._first_non_empty(aapt2_identity.get("launchable_activity")),
            "target_sdk": self._first_non_empty(
                androguard_metadata.get("target_sdk"),
                aapt2_identity.get("target_sdk_version"),
            ),
            "min_sdk": self._first_non_empty(
                androguard_metadata.get("min_sdk"),
                aapt2_identity.get("min_sdk_version"),
            ),
            "max_sdk": "",
            "version_name": self._first_non_empty(
                androguard_metadata.get("version_name"),
                aapt2_identity.get("version_name"),
            ),
            "app_store_id": "",
            "developer": "",
            "categories": "",
            "trackers_detected": "",
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
