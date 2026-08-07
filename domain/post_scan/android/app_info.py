from dataclasses import dataclass
from typing import Any

from domain.post_scan.utilities import first_non_empty


@dataclass
class AndroidAppInfo:
    icon_path: str
    name: str
    package_name: str
    main_activity: str
    target_sdk: str
    min_sdk: str
    max_sdk: str
    version_name: str
    debuggable: str
    allow_backup: str
    app_store_id: str
    developer: str
    categories: str
    trackers_detected: str

    def __init__(self, loaded_outputs: dict[str, Any]):
        androguard_metadata = loaded_outputs.get("androguard_metadata") or {}
        aapt2_identity = loaded_outputs.get("aapt2_identity") or {}
        apktool_manifest_summary = loaded_outputs.get("apktool_manifest_summary") or {}
        manifest_application = apktool_manifest_summary.get("application") or {}
        self.icon_path = ""
        self.name = first_non_empty(
            androguard_metadata.get("app_name"),
            aapt2_identity.get("application_label"),
        )
        self.package_name = first_non_empty(
            androguard_metadata.get("package"),
            aapt2_identity.get("package_name"),
        )
        self.main_activity = first_non_empty(aapt2_identity.get("launchable_activity"))
        self.target_sdk = first_non_empty(
            androguard_metadata.get("target_sdk"),
            aapt2_identity.get("target_sdk_version"),
        )
        self.min_sdk = first_non_empty(
            androguard_metadata.get("min_sdk"),
            aapt2_identity.get("min_sdk_version"),
        )
        self.max_sdk = ""
        self.version_name = first_non_empty(
            androguard_metadata.get("version_name"),
            aapt2_identity.get("version_name"),
        )
        self.debuggable = first_non_empty(
            manifest_application.get("debuggable"),
        )
        self.allow_backup = first_non_empty(
            manifest_application.get("allow_backup"),
        )
        self.app_store_id = ""
        self.developer = ""
        self.categories = ""
        self.trackers_detected = ""
