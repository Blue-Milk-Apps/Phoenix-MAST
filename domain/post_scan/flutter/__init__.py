"""Flutter post-scan domain models and rule contracts."""

from domain.post_scan.flutter.app_components import FlutterAppComponents
from domain.post_scan.flutter.app_info import FlutterAppInfo
from domain.post_scan.flutter.application import FlutterApplication
from domain.post_scan.flutter.dependency_inventory import (
    FlutterDeclaredDependency,
    FlutterDependencyInventory,
    FlutterResolvedDependency,
    FlutterSbomPackage,
)
from domain.post_scan.flutter.file_info import FlutterFileInfo
from domain.post_scan.flutter.functionality import FlutterFunctionality
from domain.post_scan.flutter.hardcoded_values import FlutterHardcodedValues
from domain.post_scan.flutter.links import FlutterDeepLinks, FlutterURLSchemes
from domain.post_scan.flutter.meta import FlutterMeta
from domain.post_scan.flutter.permissions import FlutterPermission, FlutterPermissions
from domain.post_scan.flutter.platform_inventory import (
    FlutterAndroidPlatformInventory,
    FlutterIOSPlatformInventory,
    FlutterPlatformInventory,
    FlutterSdkInventory,
)
from domain.post_scan.flutter.scan_extraction_context import FlutterScanExtractionContext

__all__ = [
    "FlutterAppInfo",
    "FlutterAppComponents",
    "FlutterApplication",
    "FlutterAndroidPlatformInventory",
    "FlutterDeclaredDependency",
    "FlutterDependencyInventory",
    "FlutterFileInfo",
    "FlutterFunctionality",
    "FlutterHardcodedValues",
    "FlutterDeepLinks",
    "FlutterIOSPlatformInventory",
    "FlutterMeta",
    "FlutterPlatformInventory",
    "FlutterPermission",
    "FlutterPermissions",
    "FlutterResolvedDependency",
    "FlutterScanExtractionContext",
    "FlutterSdkInventory",
    "FlutterSbomPackage",
    "FlutterURLSchemes",
]
