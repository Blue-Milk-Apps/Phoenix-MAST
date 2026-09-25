"""Build native Android network evidence from source scan artifacts."""

from __future__ import annotations

from dataclasses import dataclass

from domain.post_scan.android.native.scan_extraction_context import NativeAndroidScanExtractionContext
from domain.post_scan.android.native.security_evidence import (
    NativeAndroidEvidenceEntry,
    optional_bool_entry,
)


@dataclass
class NativeAndroidNetworkEvidence:
    allows_cleartext_traffic_for_all_domains: NativeAndroidEvidenceEntry
    assessed: bool

    def __init__(self, context: NativeAndroidScanExtractionContext) -> None:
        application = context.source_metadata.get("application")
        application = application if isinstance(application, dict) else {}
        self.allows_cleartext_traffic_for_all_domains = optional_bool_entry(
            application.get("uses_cleartext_traffic"),
            label="uses_cleartext_traffic",
        )
        self.assessed = self.allows_cleartext_traffic_for_all_domains.present is not None
