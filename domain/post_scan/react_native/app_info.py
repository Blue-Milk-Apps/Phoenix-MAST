"""Build React Native source application information."""

from __future__ import annotations

from dataclasses import dataclass

from domain.post_scan.react_native.meta import ReactNativeMeta
from domain.post_scan.react_native.scan_extraction_context import ReactNativeScanExtractionContext


@dataclass
class ReactNativeAppInfo:
    icon_path: str
    name: str
    package_name: str
    main_activity: str
    target_sdk: str
    min_sdk: str
    max_sdk: str
    version_name: str
    version_code: str
    description: str
    react_native_version: str
    react_version: str
    expo_version: str
    node_engine: str
    android_application_id: str
    ios_bundle_identifier: str
    app_store_id: str
    developer: str
    categories: str
    trackers_detected: str

    def __init__(self, context: ReactNativeScanExtractionContext) -> None:
        meta = ReactNativeMeta(context)
        identity = context.identity
        framework = context.framework
        engines = context.engines
        android_identity = context.android_identity
        android_application = context.android_application
        ios_identity = context.ios_identity

        self.icon_path = context.first_non_empty(android_application.get("icon"))
        self.name = meta.app_display_name
        self.package_name = meta.package_name
        self.main_activity = context.first_non_empty(android_identity.get("main_activity"))
        self.target_sdk = context.first_non_empty(android_identity.get("target_sdk"))
        self.min_sdk = context.first_non_empty(android_identity.get("min_sdk"))
        self.max_sdk = ""
        self.version_name = meta.version_name
        self.version_code = meta.version_code
        self.description = context.first_non_empty(identity.get("description"))
        self.react_native_version = context.first_non_empty(framework.get("react_native_version"))
        self.react_version = context.first_non_empty(framework.get("react_version"))
        self.expo_version = context.first_non_empty(framework.get("expo_version"))
        self.node_engine = context.first_non_empty(engines.get("node"))
        self.android_application_id = context.first_non_empty(android_identity.get("package_name"))
        self.ios_bundle_identifier = context.first_non_empty(ios_identity.get("bundle_identifier"))
        self.app_store_id = ""
        self.developer = ""
        self.categories = ""
        self.trackers_detected = ""
