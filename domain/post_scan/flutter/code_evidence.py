"""Build Flutter code evidence from Dart and embedded-platform source scans."""

from __future__ import annotations

import re
from dataclasses import dataclass

from domain.post_scan.android.rule_registry import REPORT_RULE_IDS_BY_SECTION as ANDROID_RULE_IDS
from domain.post_scan.flutter.hardcoded_values import FlutterHardcodedValues
from domain.post_scan.flutter.rule_registry import REPORT_RULE_IDS_BY_SECTION as FLUTTER_RULE_IDS
from domain.post_scan.flutter.scan_extraction_context import FlutterScanExtractionContext
from domain.post_scan.flutter.security_evidence import (
    FlutterEvidenceEntry,
    combine_evidence_entries,
    optional_bool_entry,
    scoped_opengrep_entry,
)
from domain.post_scan.ios.rule_registry import CODE_RULE_IDS_BY_EVIDENCE_KEY as IOS_CODE_RULE_IDS


@dataclass
class FlutterCodeEvidence:
    app_is_debuggable: FlutterEvidenceEntry
    activities_accessible_to_other_apps: FlutterEvidenceEntry
    receivers_accessible_to_other_apps: FlutterEvidenceEntry
    services_accessible_to_other_apps: FlutterEvidenceEntry
    application_data_can_be_backed_up: FlutterEvidenceEntry
    application_uses_custom_url_schemes_or_deep_links: FlutterEvidenceEntry
    contains_hard_coded_cryptographic_key: FlutterEvidenceEntry
    contains_potential_hard_coded_password: FlutterEvidenceEntry
    contains_potential_sql_injection: FlutterEvidenceEntry
    contains_reflection_code: FlutterEvidenceEntry
    creates_blowfish_key_with_weak_length: FlutterEvidenceEntry
    creates_rsa_keys_with_weak_modulus_length: FlutterEvidenceEntry
    requests_root_access: FlutterEvidenceEntry
    uses_sha1_hashing_algorithm: FlutterEvidenceEntry
    weakly_configured_xml_parser: FlutterEvidenceEntry
    writes_sensitive_information_to_system_log: FlutterEvidenceEntry
    uses_spoofable_values_for_authentication: FlutterEvidenceEntry
    copies_sensitive_information_into_clipboard_without_user_consent: FlutterEvidenceEntry
    uses_uiwebview: FlutterEvidenceEntry
    insecure_nanopb_library: FlutterEvidenceEntry
    insecure_nskeyedunarchiver_usage: FlutterEvidenceEntry
    encodes_data_using_insecure_cryptography: FlutterEvidenceEntry
    utilizes_insecure_cryptography: FlutterEvidenceEntry
    pbkdf2_iteration_count_below_10k: FlutterEvidenceEntry
    hardcoded_api_keys_in_bundle: FlutterEvidenceEntry
    insecure_entitlements: FlutterEvidenceEntry
    assessed: bool

    INSECURE_ENTITLEMENT_KEYS = frozenset(
        {
            "get-task-allow",
            "com.apple.security.cs.allow-dyld-environment-variables",
            "com.apple.security.cs.allow-unsigned-executable-memory",
            "com.apple.security.cs.disable-executable-page-protection",
            "com.apple.security.cs.disable-library-validation",
        }
    )

    def __init__(self, context: FlutterScanExtractionContext) -> None:
        application = context.android_application
        self.app_is_debuggable = optional_bool_entry(application.get("debuggable"), label="debuggable")
        self.application_data_can_be_backed_up = optional_bool_entry(
            application.get("allow_backup"),
            label="allow_backup",
        )
        self.activities_accessible_to_other_apps = self._component_entry(context, "activities")
        self.receivers_accessible_to_other_apps = self._component_entry(context, "receivers")
        self.services_accessible_to_other_apps = self._component_entry(context, "services")
        self.application_uses_custom_url_schemes_or_deep_links = self._deep_link_entry(context)

        hardcoded = FlutterHardcodedValues(context)
        self.contains_hard_coded_cryptographic_key = self._secret_entry(
            hardcoded,
            ("key", "token", "secret"),
            "no_hardcoded_cryptographic_key_hits",
        )
        self.contains_potential_hard_coded_password = self._secret_entry(
            hardcoded,
            ("password", "passwd", "passcode", "pwd"),
            "no_hardcoded_password_hits",
        )
        self.hardcoded_api_keys_in_bundle = self._secret_entry(
            hardcoded,
            ("api key", "api_key", "apikey", "api token"),
            "no_hardcoded_api_keys_in_bundle_hits",
        )

        rule_evidence_keys = set(FLUTTER_RULE_IDS["Code"]) | set(ANDROID_RULE_IDS["Code"]) | set(IOS_CODE_RULE_IDS)
        for evidence_key in rule_evidence_keys:
            setattr(self, evidence_key, self._rule_entry(context, evidence_key))

        self.insecure_nanopb_library = self._nanopb_entry(context)
        self.insecure_entitlements = self._entitlement_entry(context)
        self.assessed = any(
            entry.present is not None
            for name, entry in vars(self).items()
            if name != "assessed" and isinstance(entry, FlutterEvidenceEntry)
        )

    @classmethod
    def _rule_entry(
        cls,
        context: FlutterScanExtractionContext,
        evidence_key: str,
    ) -> FlutterEvidenceEntry:
        rules_by_scope = {
            "flutter": FLUTTER_RULE_IDS["Code"].get(evidence_key, frozenset()),
            "android": ANDROID_RULE_IDS["Code"].get(evidence_key, frozenset()),
            "ios": IOS_CODE_RULE_IDS.get(evidence_key, frozenset()),
        }
        entries = [
            scoped_opengrep_entry(
                context,
                scope=scope,
                rule_ids=rule_ids,
                absent_evidence=f"no_{evidence_key}_{scope}_hits",
            )
            for scope, rule_ids in rules_by_scope.items()
            if rule_ids and cls._scope_applicable(context, scope)
        ]
        return combine_evidence_entries(entries, absent_evidence=f"no_{evidence_key}_hits")

    @staticmethod
    def _scope_applicable(context: FlutterScanExtractionContext, scope: str) -> bool:
        if scope == "flutter":
            return True
        if scope == "android" and (context.platforms.get("android", False) or context.android_available):
            return True
        if scope == "ios" and (context.platforms.get("ios", False) or context.ios_available):
            return True
        if context.opengrep_results_for_scope(scope):
            return True
        scope_metadata = context.opengrep_scope(scope)
        return bool(scope_metadata) and scope_metadata.get("status") != "skipped"

    @staticmethod
    def _component_entry(context: FlutterScanExtractionContext, key: str) -> FlutterEvidenceEntry:
        components = context.android_metadata.get("components")
        if not isinstance(components, dict) or not isinstance(components.get(key), list):
            return FlutterEvidenceEntry(None)
        values = components[key]
        exported = [
            context.first_non_empty(item.get("name"))
            for item in values
            if isinstance(item, dict) and item.get("exported") is True
        ]
        exported = [name for name in exported if name]
        label = f"exported_{key}"
        if exported:
            return FlutterEvidenceEntry(True, f"{label}={len(exported)}", exported)
        if any(isinstance(item, dict) and not isinstance(item.get("exported"), bool) for item in values):
            return FlutterEvidenceEntry(None)
        return FlutterEvidenceEntry(False, f"{label}=0", [])

    @staticmethod
    def _deep_link_entry(context: FlutterScanExtractionContext) -> FlutterEvidenceEntry:
        raw = context.android_metadata.get("deep_links")
        if not isinstance(raw, list):
            return FlutterEvidenceEntry(None)
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
        return FlutterEvidenceEntry(bool(raw), f"deep_links={len(raw)}", details)

    @staticmethod
    def _secret_entry(
        hardcoded: FlutterHardcodedValues,
        terms: tuple[str, ...],
        absent_evidence: str,
    ) -> FlutterEvidenceEntry:
        matches = [
            item for item in hardcoded.secrets if any(term in item.get("value", "").casefold() for term in terms)
        ]
        if matches:
            details = [item["location"] or item["value"] for item in matches]
            details = list(dict.fromkeys(details))
            return FlutterEvidenceEntry(True, ", ".join(details[:5]), details[:10])
        if hardcoded.assessed:
            return FlutterEvidenceEntry(False, absent_evidence, [])
        return FlutterEvidenceEntry(None)

    @staticmethod
    def _nanopb_entry(context: FlutterScanExtractionContext) -> FlutterEvidenceEntry:
        matches: list[str] = []
        for output_path, package_name, version in context.syft_packages:
            if "nanopb" not in package_name.casefold():
                continue
            if not version or re.match(r"^(?:0|1)\.", version):
                label = f"{package_name}@{version}" if version else package_name
                matches.append(f"{output_path}: {label}")
        matches = list(dict.fromkeys(matches))
        if matches:
            return FlutterEvidenceEntry(True, "; ".join(matches[:5]), matches[:10])
        if context.syft_assessed:
            return FlutterEvidenceEntry(False, "no_insecure_nanopb_library_hits", [])
        return FlutterEvidenceEntry(None)

    @classmethod
    def _entitlement_entry(cls, context: FlutterScanExtractionContext) -> FlutterEvidenceEntry:
        if not cls._scope_applicable(context, "ios"):
            return FlutterEvidenceEntry(None)
        detected: set[str] = set()
        for document in context.plist_outputs_for_role("entitlements").values():
            plist = document.get("plist")
            if not isinstance(plist, dict):
                continue
            detected.update(key for key in cls.INSECURE_ENTITLEMENT_KEYS if plist.get(key) is True)
            detected.update(str(key) for key in plist if str(key).startswith("com.apple.private."))
        if detected:
            details = sorted(detected)
            return FlutterEvidenceEntry(True, ", ".join(details), details)
        if context.plist_assessed:
            return FlutterEvidenceEntry(False, "no_insecure_entitlements_hits", [])
        return FlutterEvidenceEntry(None)
