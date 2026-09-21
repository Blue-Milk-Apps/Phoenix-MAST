"""Build Flutter SDK and generated-platform inventory."""

from __future__ import annotations

from dataclasses import dataclass

from domain.post_scan.flutter.scan_extraction_context import FlutterScanExtractionContext


@dataclass
class FlutterSdkInventory:
    dart_constraint: str
    flutter_constraint: str

    def __init__(self, context: FlutterScanExtractionContext) -> None:
        self.dart_constraint = context.first_non_empty(context.sdk.get("dart_constraint"))
        self.flutter_constraint = context.first_non_empty(context.sdk.get("flutter_constraint"))


@dataclass
class FlutterAndroidPlatformInventory:
    detected: bool
    metadata_assessed: bool
    app_name: str
    package_name: str
    namespace: str
    main_activity: str
    compile_sdk: str
    min_sdk: str
    target_sdk: str
    version_name: str
    version_code: str

    def __init__(self, context: FlutterScanExtractionContext) -> None:
        identity = context.android_identity
        flutter_identity = context.identity
        self.detected = context.platforms.get("android", False) or context.android_available
        self.metadata_assessed = context.android_metadata_assessed
        self.app_name = context.first_non_empty(identity.get("app_name"))
        self.package_name = context.first_non_empty(identity.get("package_name"))
        self.namespace = context.first_non_empty(identity.get("namespace"))
        self.main_activity = context.first_non_empty(identity.get("main_activity"))
        self.compile_sdk = context.first_non_empty(identity.get("compile_sdk"))
        self.min_sdk = context.first_non_empty(identity.get("min_sdk"))
        self.target_sdk = context.first_non_empty(identity.get("target_sdk"))
        self.version_name = context.first_non_empty(
            identity.get("version_name"),
            flutter_identity.get("version_name"),
        )
        self.version_code = context.first_non_empty(
            identity.get("version_code"),
            flutter_identity.get("version_code"),
        )


@dataclass
class FlutterIOSPlatformInventory:
    detected: bool
    metadata_assessed: bool
    display_name: str
    bundle_name: str
    bundle_identifier: str
    executable: str
    minimum_os: str
    version_name: str
    version_code: str

    def __init__(self, context: FlutterScanExtractionContext) -> None:
        identity = context.ios_identity
        flutter_identity = context.identity
        self.detected = context.platforms.get("ios", False) or context.ios_available
        self.metadata_assessed = context.ios_metadata_assessed
        self.display_name = context.first_non_empty(identity.get("display_name"))
        self.bundle_name = context.first_non_empty(identity.get("bundle_name"))
        self.bundle_identifier = context.first_non_empty(identity.get("bundle_identifier"))
        self.executable = context.first_non_empty(identity.get("executable"))
        self.minimum_os = context.first_non_empty(identity.get("minimum_os"))
        self.version_name = context.first_non_empty(
            identity.get("version"),
            flutter_identity.get("version_name"),
        )
        self.version_code = context.first_non_empty(
            identity.get("build"),
            flutter_identity.get("version_code"),
        )


@dataclass
class FlutterPlatformInventory:
    source_metadata_assessed: bool
    sdk: FlutterSdkInventory
    android: FlutterAndroidPlatformInventory
    ios: FlutterIOSPlatformInventory
    web_detected: bool
    linux_detected: bool
    macos_detected: bool
    windows_detected: bool
    warnings: list[str]

    def __init__(self, context: FlutterScanExtractionContext) -> None:
        platforms = context.platforms
        self.source_metadata_assessed = context.source_metadata_assessed
        self.sdk = FlutterSdkInventory(context)
        self.android = FlutterAndroidPlatformInventory(context)
        self.ios = FlutterIOSPlatformInventory(context)
        self.web_detected = platforms.get("web", False)
        self.linux_detected = platforms.get("linux", False)
        self.macos_detected = platforms.get("macos", False)
        self.windows_detected = platforms.get("windows", False)
        self.warnings = context.warnings
