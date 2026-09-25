"""Build the default iOS app info section for post-scan reports."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from domain.post_scan.ios.binary.meta import IOSMeta, IOSProjectMetadata
from domain.post_scan.utilities import first_non_empty


@dataclass
class IOSAppInfo:
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

    def __init__(self, loaded_outputs: dict[str, Any]) -> None:
        meta = IOSMeta(loaded_outputs)
        project_metadata = IOSProjectMetadata.from_loaded_outputs(loaded_outputs)
        plist_outputs = loaded_outputs.get("plist_outputs") or {}
        primary_plist = plist_outputs.get("Info.json") if isinstance(plist_outputs, dict) else None
        app_meta = primary_plist.get("app_meta") if isinstance(primary_plist, dict) else None
        self.icon_path = ""
        self.icon_data_uri = first_non_empty(app_meta.get("icon_data_uri")) if isinstance(app_meta, dict) else ""
        self.name = first_non_empty(meta.app_display_name)
        self.package_name = first_non_empty(meta.package_name)
        self.main_activity = first_non_empty(project_metadata.main_executable_name)
        self.version_name = self._display_version(
            first_non_empty(meta.version_name),
            first_non_empty(meta.version_code),
        )
        self.app_store_id = ""
        self.developer = ""
        self.categories = ""
        self.trackers_detected = ""

    @staticmethod
    def _display_version(version_name: str, version_code: str) -> str:
        if version_name and version_code:
            return f"{version_name} ({version_code})"
        return first_non_empty(version_name, version_code)
