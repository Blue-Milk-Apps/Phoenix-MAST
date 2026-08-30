"""Build Flutter network evidence from Dart and embedded-platform source scans."""

from __future__ import annotations

from dataclasses import dataclass

from domain.post_scan.android.rule_registry import REPORT_RULE_IDS_BY_SECTION as ANDROID_RULE_IDS
from domain.post_scan.flutter.rule_registry import REPORT_RULE_IDS_BY_SECTION as FLUTTER_RULE_IDS
from domain.post_scan.flutter.scan_extraction_context import FlutterScanExtractionContext
from domain.post_scan.flutter.security_evidence import (
    FlutterEvidenceEntry,
    combine_evidence_entries,
    opengrep_scope_applicable,
    optional_bool_entry,
    scoped_opengrep_entry,
)
from domain.post_scan.ios.rule_registry import NETWORK_RULE_IDS_BY_EVIDENCE_KEY as IOS_NETWORK_RULE_IDS


@dataclass
class FlutterNetworkEvidence:
    allows_cleartext_traffic_for_all_domains: FlutterEvidenceEntry
    contains_hostname_verifier_accepts_all: FlutterEvidenceEntry
    contains_x509_trust_manager_accepts_all: FlutterEvidenceEntry
    opens_listening_port: FlutterEvidenceEntry
    sensitive_information_unencrypted_in_transit: FlutterEvidenceEntry
    weak_certificate_validation_enables_mitm: FlutterEvidenceEntry
    ats_disabled: FlutterEvidenceEntry
    ats_exceptions_configured: FlutterEvidenceEntry
    cookie_missing_httponly: FlutterEvidenceEntry
    cookie_missing_secure_flag: FlutterEvidenceEntry
    assessed: bool

    WEAK_TLS_VERSIONS = frozenset({"tlsv1", "tlsv1.0", "tlsv1.1"})

    def __init__(self, context: FlutterScanExtractionContext) -> None:
        self.allows_cleartext_traffic_for_all_domains = optional_bool_entry(
            context.android_application.get("uses_cleartext_traffic"),
            label="uses_cleartext_traffic",
        )

        rule_evidence_keys = (
            set(FLUTTER_RULE_IDS["Network"]) | set(ANDROID_RULE_IDS["Network"]) | set(IOS_NETWORK_RULE_IDS)
        )
        for evidence_key in rule_evidence_keys:
            setattr(self, evidence_key, self._rule_entry(context, evidence_key))

        self.weak_certificate_validation_enables_mitm = combine_evidence_entries(
            [
                self.weak_certificate_validation_enables_mitm,
                self.contains_hostname_verifier_accepts_all,
                self.contains_x509_trust_manager_accepts_all,
            ],
            absent_evidence="no_weak_certificate_validation_hits",
        )
        self.ats_disabled = combine_evidence_entries(
            [self.ats_disabled, self._ats_disabled_metadata_entry(context)],
            absent_evidence="no_ats_disabled_hits",
        )
        self.ats_exceptions_configured = combine_evidence_entries(
            [self.ats_exceptions_configured, self._ats_exception_metadata_entry(context)],
            absent_evidence="no_ats_exceptions_configured_hits",
        )
        self.assessed = any(
            entry.present is not None
            for name, entry in vars(self).items()
            if name != "assessed" and isinstance(entry, FlutterEvidenceEntry)
        )

    @staticmethod
    def _rule_entry(
        context: FlutterScanExtractionContext,
        evidence_key: str,
    ) -> FlutterEvidenceEntry:
        rules_by_scope = {
            "flutter": FLUTTER_RULE_IDS["Network"].get(evidence_key, frozenset()),
            "android": ANDROID_RULE_IDS["Network"].get(evidence_key, frozenset()),
            "ios": IOS_NETWORK_RULE_IDS.get(evidence_key, frozenset()),
        }
        entries = [
            scoped_opengrep_entry(
                context,
                scope=scope,
                rule_ids=rule_ids,
                absent_evidence=f"no_{evidence_key}_{scope}_hits",
            )
            for scope, rule_ids in rules_by_scope.items()
            if rule_ids and opengrep_scope_applicable(context, scope)
        ]
        return combine_evidence_entries(entries, absent_evidence=f"no_{evidence_key}_hits")

    @staticmethod
    def _ats_disabled_metadata_entry(context: FlutterScanExtractionContext) -> FlutterEvidenceEntry:
        raw_ats = context.ios_metadata.get("app_transport_security")
        if not context.ios_metadata_assessed or not isinstance(raw_ats, dict):
            return FlutterEvidenceEntry(None)
        present = raw_ats.get("allows_arbitrary_loads") is True
        return FlutterEvidenceEntry(
            present,
            "NSAllowsArbitraryLoads=true" if present else "NSAllowsArbitraryLoads=false",
            ["NSAllowsArbitraryLoads"] if present else [],
        )

    @classmethod
    def _ats_exception_metadata_entry(cls, context: FlutterScanExtractionContext) -> FlutterEvidenceEntry:
        raw_ats = context.ios_metadata.get("app_transport_security")
        if not context.ios_metadata_assessed or not isinstance(raw_ats, dict):
            return FlutterEvidenceEntry(None)

        details: list[str] = []
        if raw_ats.get("allows_arbitrary_loads_for_media") is True:
            details.append("NSAllowsArbitraryLoadsForMedia=true")
        if raw_ats.get("allows_arbitrary_loads_in_web_content") is True:
            details.append("NSAllowsArbitraryLoadsInWebContent=true")
        exception_domains = raw_ats.get("exception_domains")
        if isinstance(exception_domains, list):
            for exception in exception_domains:
                if not isinstance(exception, dict):
                    continue
                domain = context.first_non_empty(exception.get("domain"), "unknown domain")
                if exception.get("allows_insecure_http_loads") is True:
                    details.append(f"{domain}: allows_insecure_http_loads=true")
                minimum_tls = context.first_non_empty(exception.get("minimum_tls_version"))
                if minimum_tls.casefold() in cls.WEAK_TLS_VERSIONS:
                    details.append(f"{domain}: minimum_tls_version={minimum_tls}")
                if exception.get("requires_forward_secrecy") is False:
                    details.append(f"{domain}: requires_forward_secrecy=false")
        details = list(dict.fromkeys(details))
        if details:
            return FlutterEvidenceEntry(True, "; ".join(details[:5]), details[:10])
        return FlutterEvidenceEntry(False, "no_ats_metadata_exceptions", [])
