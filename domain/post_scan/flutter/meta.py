"""Build Flutter source metadata for post-scan reports."""

from __future__ import annotations

from dataclasses import dataclass

from domain.post_scan.flutter.scan_extraction_context import FlutterScanExtractionContext


@dataclass
class FlutterMeta:
    app_display_name: str
    file_name: str
    package_name: str
    platform: str
    reviewer_org: str
    scan_date: str
    target_type: str
    version_code: str
    version_name: str

    def __init__(self, context: FlutterScanExtractionContext) -> None:
        identity = context.identity
        android_identity = context.android_identity
        ios_identity = context.ios_identity
        project_path = context.project_path

        self.app_display_name = context.first_non_empty(
            identity.get("app_name"),
            android_identity.get("app_name"),
            ios_identity.get("display_name"),
            ios_identity.get("bundle_name"),
            identity.get("package_name"),
            project_path.stem,
            project_path.name,
        )
        self.file_name = project_path.name
        self.package_name = context.first_non_empty(identity.get("package_name"))
        self.platform = "Flutter"
        self.reviewer_org = "Phoenix Security Report"
        self.scan_date = context.scan_date
        self.target_type = str(context.scan_metadata.get("target_type") or "SOURCE").strip().upper()
        self.version_code = context.first_non_empty(identity.get("version_code"))
        self.version_name = context.first_non_empty(identity.get("version_name"))
