"""Build native iOS source app information."""

from __future__ import annotations

from dataclasses import dataclass

from domain.post_scan.ios.native.meta import NativeIOSMeta
from domain.post_scan.ios.native.scan_extraction_context import NativeIOSScanExtractionContext


@dataclass
class NativeIOSAppInfo:
    icon_path: str
    icon_data_uri: str
    name: str
    package_name: str
    main_activity: str
    version_name: str
    app_store_id: str
    developer: str
    categories: str
    trackers_detected: str

    def __init__(self, context: NativeIOSScanExtractionContext) -> None:
        meta = NativeIOSMeta(context)
        app_meta = context.primary_app_meta
        if meta.version_name and meta.version_code:
            version = f"{meta.version_name} ({meta.version_code})"
        else:
            version = meta.version_name or meta.version_code
        self.icon_path = ""
        self.icon_data_uri = context.first_non_empty(app_meta.get("icon_data_uri"))
        self.name = meta.app_display_name
        self.package_name = meta.package_name
        self.main_activity = context.first_non_empty(app_meta.get("executable"))
        self.version_name = version
        self.app_store_id = ""
        self.developer = ""
        self.categories = ""
        self.trackers_detected = ""
