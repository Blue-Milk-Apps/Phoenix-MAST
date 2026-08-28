"""Build native Android resilience evidence from source scan artifacts."""

from __future__ import annotations

from dataclasses import dataclass

from domain.post_scan.android.native.scan_extraction_context import NativeAndroidScanExtractionContext
from domain.post_scan.android.native.security_evidence import NativeAndroidEvidenceEntry, opengrep_entry
from domain.post_scan.android.rule_registry import REPORT_RULE_IDS_BY_SECTION


@dataclass
class NativeAndroidResilienceEvidence:
    biometric_local_authentication_bypass_possible: NativeAndroidEvidenceEntry
    assessed: bool

    def __init__(self, context: NativeAndroidScanExtractionContext) -> None:
        rule_ids = REPORT_RULE_IDS_BY_SECTION["Resilience"]["biometric_local_authentication_bypass_possible"]
        self.biometric_local_authentication_bypass_possible = opengrep_entry(
            context,
            rule_ids,
            "no_biometric_local_authentication_bypass_possible_hits",
        )
        self.assessed = self.biometric_local_authentication_bypass_possible.present is not None
