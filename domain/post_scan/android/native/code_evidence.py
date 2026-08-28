"""Build native Android code evidence from source scan artifacts."""

from __future__ import annotations

from dataclasses import dataclass

from domain.post_scan.android.native.hardcoded_values import NativeAndroidHardcodedValues
from domain.post_scan.android.native.scan_extraction_context import NativeAndroidScanExtractionContext
from domain.post_scan.android.native.security_evidence import (
    NativeAndroidEvidenceEntry,
    opengrep_entry,
    optional_bool_entry,
)
from domain.post_scan.android.rule_registry import REPORT_RULE_IDS_BY_SECTION


@dataclass
class NativeAndroidCodeEvidence:
    app_is_debuggable: NativeAndroidEvidenceEntry
    activities_accessible_to_other_apps: NativeAndroidEvidenceEntry
    receivers_accessible_to_other_apps: NativeAndroidEvidenceEntry
    services_accessible_to_other_apps: NativeAndroidEvidenceEntry
    application_data_can_be_backed_up: NativeAndroidEvidenceEntry
    application_uses_custom_url_schemes_or_deep_links: NativeAndroidEvidenceEntry
    contains_hard_coded_cryptographic_key: NativeAndroidEvidenceEntry
    contains_potential_hard_coded_password: NativeAndroidEvidenceEntry
    contains_potential_sql_injection: NativeAndroidEvidenceEntry
    contains_reflection_code: NativeAndroidEvidenceEntry
    creates_blowfish_key_with_weak_length: NativeAndroidEvidenceEntry
    creates_rsa_keys_with_weak_modulus_length: NativeAndroidEvidenceEntry
    requests_root_access: NativeAndroidEvidenceEntry
    uses_sha1_hashing_algorithm: NativeAndroidEvidenceEntry
    weakly_configured_xml_parser: NativeAndroidEvidenceEntry
    writes_sensitive_information_to_system_log: NativeAndroidEvidenceEntry
    uses_spoofable_values_for_authentication: NativeAndroidEvidenceEntry
    copies_sensitive_information_into_clipboard_without_user_consent: NativeAndroidEvidenceEntry
    assessed: bool

    def __init__(self, context: NativeAndroidScanExtractionContext) -> None:
        application = context.source_metadata.get("application")
        application = application if isinstance(application, dict) else {}
        self.app_is_debuggable = optional_bool_entry(application.get("debuggable"), label="debuggable")
        self.application_data_can_be_backed_up = optional_bool_entry(
            application.get("allow_backup"),
            label="allow_backup",
        )
        self.activities_accessible_to_other_apps = self._component_entry(context, "activities")
        self.receivers_accessible_to_other_apps = self._component_entry(context, "receivers")
        self.services_accessible_to_other_apps = self._component_entry(context, "services")
        self.application_uses_custom_url_schemes_or_deep_links = self._deep_link_entry(context)

        hardcoded = NativeAndroidHardcodedValues(context)
        self.contains_hard_coded_cryptographic_key = self._secret_entry(
            hardcoded,
            ("key", "secret", "credential", "token"),
            "no_hardcoded_cryptographic_key_hits",
        )
        self.contains_potential_hard_coded_password = self._secret_entry(
            hardcoded,
            ("password", "passwd", "passcode", "pwd"),
            "no_hardcoded_password_hits",
        )

        for evidence_key in REPORT_RULE_IDS_BY_SECTION["Code"]:
            setattr(
                self,
                evidence_key,
                opengrep_entry(
                    context,
                    REPORT_RULE_IDS_BY_SECTION["Code"][evidence_key],
                    f"no_{evidence_key}_hits",
                ),
            )
        self.assessed = any(
            entry.present is not None
            for name, entry in vars(self).items()
            if name != "assessed" and isinstance(entry, NativeAndroidEvidenceEntry)
        )

    @staticmethod
    def _component_entry(context: NativeAndroidScanExtractionContext, key: str) -> NativeAndroidEvidenceEntry:
        components = context.source_metadata.get("components")
        if not isinstance(components, dict) or not isinstance(components.get(key), list):
            return NativeAndroidEvidenceEntry(None)
        exported = [
            context.first_non_empty(item.get("name"))
            for item in components[key]
            if isinstance(item, dict) and item.get("exported") is True
        ]
        exported = [name for name in exported if name]
        label = f"exported_{key}"
        if exported:
            return NativeAndroidEvidenceEntry(True, f"{label}={len(exported)}", exported)
        if any(isinstance(item, dict) and not isinstance(item.get("exported"), bool) for item in components[key]):
            return NativeAndroidEvidenceEntry(None)
        return NativeAndroidEvidenceEntry(False, f"{label}=0", [])

    @staticmethod
    def _deep_link_entry(context: NativeAndroidScanExtractionContext) -> NativeAndroidEvidenceEntry:
        raw = context.source_metadata.get("deep_links")
        if not isinstance(raw, list):
            return NativeAndroidEvidenceEntry(None)
        details = [
            "://".join(
                part
                for part in (
                    context.first_non_empty(item.get("scheme")),
                    context.first_non_empty(item.get("host")),
                )
                if part
            )
            for item in raw
            if isinstance(item, dict)
        ]
        details = [item for item in details if item]
        return NativeAndroidEvidenceEntry(bool(raw), f"deep_links={len(raw)}", details)

    @staticmethod
    def _secret_entry(
        hardcoded: NativeAndroidHardcodedValues,
        terms: tuple[str, ...],
        absent_evidence: str,
    ) -> NativeAndroidEvidenceEntry:
        matches = [
            item for item in hardcoded.secrets if any(term in str(item.get("value", "")).lower() for term in terms)
        ]
        if matches:
            locations = [str(item.get("location", "")) for item in matches if item.get("location")]
            return NativeAndroidEvidenceEntry(True, ", ".join(locations[:5]), locations[:10])
        if hardcoded.assessed:
            return NativeAndroidEvidenceEntry(False, absent_evidence, [])
        return NativeAndroidEvidenceEntry(None)
