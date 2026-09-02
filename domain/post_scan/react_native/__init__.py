"""React Native source post-scan domain models."""

from domain.post_scan.react_native.app_components import ReactNativeAppComponents
from domain.post_scan.react_native.app_info import ReactNativeAppInfo
from domain.post_scan.react_native.application import ReactNativeApplication
from domain.post_scan.react_native.dependency_inventory import (
    ReactNativeDeclaredDependency,
    ReactNativeDependencyInventory,
    ReactNativeSbomPackage,
)
from domain.post_scan.react_native.evidence import (
    ReactNativeCodeEvidence,
    ReactNativeDataStorageEvidence,
    ReactNativeNetworkEvidence,
    ReactNativeResilienceEvidence,
)
from domain.post_scan.react_native.file_info import ReactNativeFileInfo
from domain.post_scan.react_native.hardcoded_values import ReactNativeHardcodedValues
from domain.post_scan.react_native.links import ReactNativeDeepLinks, ReactNativeURLSchemes
from domain.post_scan.react_native.meta import ReactNativeMeta
from domain.post_scan.react_native.permissions import ReactNativePermission, ReactNativePermissions
from domain.post_scan.react_native.platform_inventory import (
    ReactNativeAndroidPlatformInventory,
    ReactNativeFrameworkInventory,
    ReactNativeIOSPlatformInventory,
    ReactNativePlatformInventory,
)
from domain.post_scan.react_native.rule_registry import (
    REACT_NATIVE_RULE_IDS,
    REACT_NATIVE_RULE_REGISTRY,
    REPORT_RULE_IDS_BY_SECTION,
    ReactNativeRuleDisposition,
    ReactNativeRuleMapping,
    unclassified_react_native_rule_ids,
)
from domain.post_scan.react_native.scan_extraction_context import ReactNativeScanExtractionContext

__all__ = [
    "REACT_NATIVE_RULE_IDS",
    "REACT_NATIVE_RULE_REGISTRY",
    "REPORT_RULE_IDS_BY_SECTION",
    "ReactNativeAndroidPlatformInventory",
    "ReactNativeAppComponents",
    "ReactNativeAppInfo",
    "ReactNativeApplication",
    "ReactNativeCodeEvidence",
    "ReactNativeDataStorageEvidence",
    "ReactNativeDeclaredDependency",
    "ReactNativeDeepLinks",
    "ReactNativeDependencyInventory",
    "ReactNativeFileInfo",
    "ReactNativeFrameworkInventory",
    "ReactNativeHardcodedValues",
    "ReactNativeIOSPlatformInventory",
    "ReactNativeMeta",
    "ReactNativeNetworkEvidence",
    "ReactNativePermission",
    "ReactNativePermissions",
    "ReactNativePlatformInventory",
    "ReactNativeResilienceEvidence",
    "ReactNativeRuleDisposition",
    "ReactNativeRuleMapping",
    "ReactNativeSbomPackage",
    "ReactNativeScanExtractionContext",
    "ReactNativeURLSchemes",
    "unclassified_react_native_rule_ids",
]
