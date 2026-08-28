"""Build native Android network evidence from source scan artifacts."""

from __future__ import annotations

from dataclasses import dataclass

from domain.post_scan.android.native.scan_extraction_context import NativeAndroidScanExtractionContext
from domain.post_scan.android.native.security_evidence import (
    NativeAndroidEvidenceEntry,
    opengrep_entry,
    optional_bool_entry,
)
from domain.post_scan.android.rule_registry import REPORT_RULE_IDS_BY_SECTION


@dataclass
class NativeAndroidNetworkEvidence:
    allows_cleartext_traffic_for_all_domains: NativeAndroidEvidenceEntry
    contains_hostname_verifier_accepts_all: NativeAndroidEvidenceEntry
    contains_x509_trust_manager_accepts_all: NativeAndroidEvidenceEntry
    opens_listening_port: NativeAndroidEvidenceEntry
    sensitive_information_unencrypted_in_transit: NativeAndroidEvidenceEntry
    weak_certificate_validation_enables_mitm: NativeAndroidEvidenceEntry
    assessed: bool

    def __init__(self, context: NativeAndroidScanExtractionContext) -> None:
        application = context.source_metadata.get("application")
        application = application if isinstance(application, dict) else {}
        self.allows_cleartext_traffic_for_all_domains = optional_bool_entry(
            application.get("uses_cleartext_traffic"),
            label="uses_cleartext_traffic",
        )
        for evidence_key in REPORT_RULE_IDS_BY_SECTION["Network"]:
            setattr(
                self,
                evidence_key,
                opengrep_entry(
                    context,
                    REPORT_RULE_IDS_BY_SECTION["Network"][evidence_key],
                    f"no_{evidence_key}_hits",
                ),
            )
        self.weak_certificate_validation_enables_mitm = self._mitm_entry()
        self.assessed = any(
            entry.present is not None
            for name, entry in vars(self).items()
            if name != "assessed" and isinstance(entry, NativeAndroidEvidenceEntry)
        )

    def _mitm_entry(self) -> NativeAndroidEvidenceEntry:
        entries = (
            self.contains_hostname_verifier_accepts_all,
            self.contains_x509_trust_manager_accepts_all,
        )
        detected = [entry for entry in entries if entry.present is True]
        if detected:
            details = [detail for entry in detected for detail in entry.details]
            evidence = "; ".join(entry.evidence for entry in detected if entry.evidence)
            return NativeAndroidEvidenceEntry(True, evidence, details)
        if all(entry.present is False for entry in entries):
            return NativeAndroidEvidenceEntry(False, "no_weak_certificate_validation_hits", [])
        return NativeAndroidEvidenceEntry(None)
