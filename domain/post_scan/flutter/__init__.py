"""Flutter post-scan domain models and rule contracts."""

from domain.post_scan.flutter.app_info import FlutterAppInfo
from domain.post_scan.flutter.code_evidence import FlutterCodeEvidence
from domain.post_scan.flutter.dependency_inventory import (
    FlutterDeclaredDependency,
    FlutterDependencyInventory,
    FlutterResolvedDependency,
    FlutterSbomPackage,
)
from domain.post_scan.flutter.file_info import FlutterFileInfo
from domain.post_scan.flutter.hardcoded_values import FlutterHardcodedValues
from domain.post_scan.flutter.meta import FlutterMeta
from domain.post_scan.flutter.network_evidence import FlutterNetworkEvidence
from domain.post_scan.flutter.opengrep_assessment import (
    FlutterOpenGrepAssessment,
    FlutterRuleAssessment,
)
from domain.post_scan.flutter.platform_inventory import (
    FlutterAndroidPlatformInventory,
    FlutterIOSPlatformInventory,
    FlutterPlatformInventory,
    FlutterSdkInventory,
)
from domain.post_scan.flutter.rule_registry import (
    FLUTTER_RULE_IDS,
    FLUTTER_RULE_REGISTRY,
    REPORT_RULE_IDS_BY_SECTION,
    FlutterRuleDisposition,
    FlutterRuleMapping,
    unclassified_flutter_rule_ids,
)
from domain.post_scan.flutter.scan_extraction_context import FlutterScanExtractionContext
from domain.post_scan.flutter.security_evidence import (
    FlutterEvidenceEntry,
    combine_evidence_entries,
    opengrep_scope_applicable,
    optional_bool_entry,
    scoped_opengrep_entry,
)

__all__ = [
    "FLUTTER_RULE_IDS",
    "FLUTTER_RULE_REGISTRY",
    "REPORT_RULE_IDS_BY_SECTION",
    "FlutterAppInfo",
    "FlutterAndroidPlatformInventory",
    "FlutterDeclaredDependency",
    "FlutterCodeEvidence",
    "FlutterDependencyInventory",
    "FlutterEvidenceEntry",
    "FlutterFileInfo",
    "FlutterHardcodedValues",
    "FlutterIOSPlatformInventory",
    "FlutterMeta",
    "FlutterNetworkEvidence",
    "FlutterOpenGrepAssessment",
    "FlutterPlatformInventory",
    "FlutterResolvedDependency",
    "FlutterRuleDisposition",
    "FlutterRuleMapping",
    "FlutterRuleAssessment",
    "FlutterScanExtractionContext",
    "FlutterSdkInventory",
    "FlutterSbomPackage",
    "combine_evidence_entries",
    "opengrep_scope_applicable",
    "optional_bool_entry",
    "scoped_opengrep_entry",
    "unclassified_flutter_rule_ids",
]
