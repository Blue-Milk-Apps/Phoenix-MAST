"""Build native Android source application information."""

from __future__ import annotations

from dataclasses import dataclass

from domain.post_scan.android.native.scan_extraction_context import NativeAndroidScanExtractionContext


@dataclass
class NativeAndroidAppInfo:
    icon_path: str
    name: str
    package_name: str
    main_activity: str
    target_sdk: str
    min_sdk: str
    max_sdk: str
    version_name: str
    debuggable: bool | None
    allow_backup: bool | None
    app_store_id: str
    developer: str
    categories: str
    trackers_detected: str

    def __init__(self, context: NativeAndroidScanExtractionContext) -> None:
        identity = context.identity
        application = context.application
        self.icon_path = context.first_non_empty(application.get("icon"))
        self.name = context.first_non_empty(
            identity.get("app_name"),
            context.project_path.stem,
            context.project_path.name,
        )
        self.package_name = context.first_non_empty(identity.get("package_name"))
        self.main_activity = context.first_non_empty(identity.get("main_activity"))
        self.target_sdk = context.first_non_empty(identity.get("target_sdk"))
        self.min_sdk = context.first_non_empty(identity.get("min_sdk"))
        self.max_sdk = ""
        self.version_name = context.first_non_empty(identity.get("version_name"))
        self.debuggable = self._optional_bool(application.get("debuggable"))
        self.allow_backup = self._optional_bool(application.get("allow_backup"))
        self.app_store_id = ""
        self.developer = ""
        self.categories = ""
        self.trackers_detected = ""

    @staticmethod
    def _optional_bool(value: object) -> bool | None:
        return value if isinstance(value, bool) else None
