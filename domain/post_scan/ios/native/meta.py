"""Build native iOS source metadata for post-scan reports."""

from __future__ import annotations

from dataclasses import dataclass

from domain.post_scan.ios.native.scan_extraction_context import NativeIOSScanExtractionContext


@dataclass
class NativeIOSMeta:
    app_display_name: str
    file_name: str
    package_name: str
    platform: str
    reviewer_org: str
    scan_date: str
    target_type: str
    version_code: str
    version_name: str

    def __init__(self, context: NativeIOSScanExtractionContext) -> None:
        app_meta = context.primary_app_meta
        project_path = context.project_path
        self.app_display_name = context.first_non_empty(
            app_meta.get("display_name"),
            app_meta.get("bundle_name"),
            project_path.stem,
            project_path.name,
        )
        self.file_name = project_path.name
        self.package_name = context.first_non_empty(app_meta.get("bundle_identifier"))
        self.platform = "iOS"
        self.reviewer_org = "Phoenix Security Report"
        self.scan_date = context.scan_date
        self.target_type = str(context.scan_metadata.get("target_type") or "SOURCE").strip().upper()
        self.version_code = context.first_non_empty(app_meta.get("build"))
        self.version_name = context.first_non_empty(app_meta.get("version"))
