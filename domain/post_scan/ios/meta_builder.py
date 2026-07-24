"""Build iOS binary meta section for post-scan reports."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from domain.post_scan.utilities import first_non_empty


@dataclass
class IOSMeta:
    app_display_name: str
    file_name: str
    package_name: str
    platform: str
    reviewer_org: str
    scan_date: str
    version_code: str
    version_name: str

    DEFAULT_REVIEWER_ORG = "Phoenix Security Report"

    def __init__(self, loaded_outputs: dict[str, Any]) -> None:
        scan_metadata = loaded_outputs.get("scan_metadata") or {}
        identity = self._identity_fields(loaded_outputs)
        project_name = Path(str(scan_metadata.get("project_path", ""))).name

        self.app_display_name = first_non_empty(
            identity.get("display_name"),
            identity.get("bundle_name"),
            project_name,
        )
        self.file_name = first_non_empty(project_name)
        self.package_name = first_non_empty(identity.get("bundle_id"))
        self.platform = "iOS"
        self.reviewer_org = self.DEFAULT_REVIEWER_ORG
        self.scan_date = first_non_empty(scan_metadata.get("scan_date"))
        self.version_code = first_non_empty(identity.get("version_code"))
        self.version_name = first_non_empty(identity.get("version_name"))

    @staticmethod
    def _identity_fields(loaded_outputs: dict[str, Any]) -> dict[str, str]:
        plist_documents = loaded_outputs.get("plist_outputs") or {}
        for document in plist_documents.values():
            if not isinstance(document, dict):
                continue
            app_meta = document.get("app_meta") or {}
            plist = document.get("plist") or {}
            if not isinstance(plist, dict):
                plist = {}
            bundle_id = first_non_empty(
                app_meta.get("bundle_identifier"),
                plist.get("CFBundleIdentifier"),
            )
            if not bundle_id:
                continue
            return {
                "bundle_id": bundle_id,
                "bundle_name": first_non_empty(
                    app_meta.get("bundle_name"),
                    plist.get("CFBundleName"),
                ),
                "display_name": first_non_empty(
                    app_meta.get("display_name"),
                    plist.get("CFBundleDisplayName"),
                    plist.get("CFBundleName"),
                ),
                "version_name": first_non_empty(
                    app_meta.get("version"),
                    plist.get("CFBundleShortVersionString"),
                ),
                "version_code": first_non_empty(
                    app_meta.get("build"),
                    plist.get("CFBundleVersion"),
                ),
            }

        ipsw_outputs = loaded_outputs.get("ipsw_outputs") or {}
        for document in ipsw_outputs.values():
            if not isinstance(document, dict):
                continue
            app_info = document.get("app_info") or {}
            if not isinstance(app_info, dict):
                continue
            bundle_id = first_non_empty(app_info.get("bundle_id"))
            if not bundle_id:
                continue
            return {
                "bundle_id": bundle_id,
                "bundle_name": first_non_empty(app_info.get("bundle_name")),
                "display_name": first_non_empty(app_info.get("bundle_name")),
                "version_name": first_non_empty(app_info.get("short_version")),
                "version_code": first_non_empty(app_info.get("bundle_version")),
            }

        return {}
