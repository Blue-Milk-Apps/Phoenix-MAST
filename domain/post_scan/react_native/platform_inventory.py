"""Build React Native framework and native-platform inventory."""

from __future__ import annotations

from dataclasses import dataclass

from domain.post_scan.react_native.scan_extraction_context import ReactNativeScanExtractionContext


@dataclass
class ReactNativeFrameworkInventory:
    react_native_version: str
    react_version: str
    expo_version: str
    typescript: bool
    node_engine: str
    npm_engine: str
    yarn_engine: str
    pnpm_engine: str
    package_manager: str
    package_main: str
    entrypoint_files: list[str]
    expo_router_path: str

    def __init__(self, context: ReactNativeScanExtractionContext) -> None:
        framework = context.framework
        engines = context.engines
        entrypoints = context.entrypoints
        self.react_native_version = context.first_non_empty(framework.get("react_native_version"))
        self.react_version = context.first_non_empty(framework.get("react_version"))
        self.expo_version = context.first_non_empty(framework.get("expo_version"))
        self.typescript = framework.get("typescript") is True
        self.node_engine = context.first_non_empty(engines.get("node"))
        self.npm_engine = context.first_non_empty(engines.get("npm"))
        self.yarn_engine = context.first_non_empty(engines.get("yarn"))
        self.pnpm_engine = context.first_non_empty(engines.get("pnpm"))
        self.package_manager = context.first_non_empty(context.project.get("package_manager"))
        self.package_main = context.first_non_empty(entrypoints.get("package_main"))
        self.entrypoint_files = context.string_list(entrypoints.get("files"))
        self.expo_router_path = context.first_non_empty(entrypoints.get("expo_router_path"))


@dataclass
class ReactNativeAndroidPlatformInventory:
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

    def __init__(self, context: ReactNativeScanExtractionContext) -> None:
        identity = context.android_identity
        self.detected = context.platforms.get("android", False) or context.android_available
        self.metadata_assessed = context.android_metadata_assessed
        self.app_name = context.first_non_empty(identity.get("app_name"))
        self.package_name = context.first_non_empty(identity.get("package_name"))
        self.namespace = context.first_non_empty(identity.get("namespace"))
        self.main_activity = context.first_non_empty(identity.get("main_activity"))
        self.compile_sdk = context.first_non_empty(identity.get("compile_sdk"))
        self.min_sdk = context.first_non_empty(identity.get("min_sdk"))
        self.target_sdk = context.first_non_empty(identity.get("target_sdk"))
        self.version_name = context.first_non_empty(identity.get("version_name"), context.identity.get("version"))
        self.version_code = context.first_non_empty(identity.get("version_code"))


@dataclass
class ReactNativeIOSPlatformInventory:
    detected: bool
    metadata_assessed: bool
    display_name: str
    bundle_name: str
    bundle_identifier: str
    executable: str
    minimum_os: str
    version_name: str
    version_code: str

    def __init__(self, context: ReactNativeScanExtractionContext) -> None:
        identity = context.ios_identity
        self.detected = context.platforms.get("ios", False) or context.ios_available
        self.metadata_assessed = context.ios_metadata_assessed
        self.display_name = context.first_non_empty(identity.get("display_name"))
        self.bundle_name = context.first_non_empty(identity.get("bundle_name"))
        self.bundle_identifier = context.first_non_empty(identity.get("bundle_identifier"))
        self.executable = context.first_non_empty(identity.get("executable"))
        self.minimum_os = context.first_non_empty(identity.get("minimum_os"))
        self.version_name = context.first_non_empty(identity.get("version"), context.identity.get("version"))
        self.version_code = context.first_non_empty(identity.get("build"))


@dataclass
class ReactNativePlatformInventory:
    source_metadata_assessed: bool
    framework: ReactNativeFrameworkInventory
    android: ReactNativeAndroidPlatformInventory
    ios: ReactNativeIOSPlatformInventory
    warnings: list[str]

    def __init__(self, context: ReactNativeScanExtractionContext) -> None:
        self.source_metadata_assessed = context.source_metadata_assessed
        self.framework = ReactNativeFrameworkInventory(context)
        self.android = ReactNativeAndroidPlatformInventory(context)
        self.ios = ReactNativeIOSPlatformInventory(context)
        self.warnings = context.warnings
