"""Build Flutter resilience evidence from available embedded-platform signals."""

from __future__ import annotations

from dataclasses import dataclass

from domain.post_scan.android.rule_registry import REPORT_RULE_IDS_BY_SECTION as ANDROID_RULE_IDS
from domain.post_scan.flutter.scan_extraction_context import FlutterScanExtractionContext
from domain.post_scan.flutter.security_evidence import (
    FlutterEvidenceEntry,
    opengrep_scope_applicable,
    scoped_opengrep_entry,
)


@dataclass
class FlutterResilienceEvidence:
    biometric_local_authentication_bypass_possible: FlutterEvidenceEntry
    assessed: bool

    def __init__(self, context: FlutterScanExtractionContext) -> None:
        rule_ids = ANDROID_RULE_IDS["Resilience"]["biometric_local_authentication_bypass_possible"]
        if opengrep_scope_applicable(context, "android"):
            self.biometric_local_authentication_bypass_possible = scoped_opengrep_entry(
                context,
                scope="android",
                rule_ids=rule_ids,
                absent_evidence="no_biometric_local_authentication_bypass_possible_hits",
            )
        else:
            self.biometric_local_authentication_bypass_possible = FlutterEvidenceEntry(None)
        self.assessed = self.biometric_local_authentication_bypass_possible.present is not None
