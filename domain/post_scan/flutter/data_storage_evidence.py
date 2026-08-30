"""Build Flutter data-storage evidence from Dart and embedded-platform source scans."""

from __future__ import annotations

from dataclasses import dataclass

from domain.post_scan.android.rule_registry import REPORT_RULE_IDS_BY_SECTION as ANDROID_RULE_IDS
from domain.post_scan.flutter.rule_registry import REPORT_RULE_IDS_BY_SECTION as FLUTTER_RULE_IDS
from domain.post_scan.flutter.scan_extraction_context import FlutterScanExtractionContext
from domain.post_scan.flutter.security_evidence import (
    FlutterEvidenceEntry,
    combine_evidence_entries,
    opengrep_scope_applicable,
    scoped_opengrep_entry,
)
from domain.post_scan.ios.rule_registry import DATA_STORAGE_RULE_IDS_BY_EVIDENCE_KEY as IOS_STORAGE_RULE_IDS


@dataclass
class FlutterDataStorageEvidence:
    accesses_external_storage: FlutterEvidenceEntry
    sensitive_information_stored_in_world_readable_or_writable_file_in_internal_storage: FlutterEvidenceEntry
    sensitive_information_stored_in_external_storage: FlutterEvidenceEntry
    weak_file_protection: FlutterEvidenceEntry
    deprecated_keychain_attributes: FlutterEvidenceEntry
    advertiser_id_stored_insecurely: FlutterEvidenceEntry
    imei_labeled_value_stored_insecurely: FlutterEvidenceEntry
    global_write_permissions: FlutterEvidenceEntry
    location_data_stored_insecurely: FlutterEvidenceEntry
    hardcoded_api_keys_stored_insecurely: FlutterEvidenceEntry
    hardcoded_passwords_stored_insecurely: FlutterEvidenceEntry
    sensitive_values_stored_insecurely: FlutterEvidenceEntry
    wifi_ip_stored_insecurely: FlutterEvidenceEntry
    keychain_items_accessible_after_first_unlock: FlutterEvidenceEntry
    sensitive_data_stored_in_user_defaults: FlutterEvidenceEntry
    advertiser_id_logged_insecurely: FlutterEvidenceEntry
    imei_logged_insecurely: FlutterEvidenceEntry
    location_data_logged_insecurely: FlutterEvidenceEntry
    sensitive_data_logged_insecurely: FlutterEvidenceEntry
    wifi_mac_logged_insecurely: FlutterEvidenceEntry
    keyboard_cache_exposure: FlutterEvidenceEntry
    assessed: bool

    EXTERNAL_STORAGE_PERMISSIONS = frozenset(
        {
            "android.permission.READ_EXTERNAL_STORAGE",
            "android.permission.WRITE_EXTERNAL_STORAGE",
            "android.permission.MANAGE_EXTERNAL_STORAGE",
            "android.permission.READ_MEDIA_AUDIO",
            "android.permission.READ_MEDIA_IMAGES",
            "android.permission.READ_MEDIA_VIDEO",
        }
    )

    def __init__(self, context: FlutterScanExtractionContext) -> None:
        self.accesses_external_storage = self._external_storage_entry(context)

        rule_evidence_keys = (
            set(FLUTTER_RULE_IDS["Data Storage"]) | set(ANDROID_RULE_IDS["Data Storage"]) | set(IOS_STORAGE_RULE_IDS)
        )
        for evidence_key in rule_evidence_keys:
            setattr(self, evidence_key, self._rule_entry(context, evidence_key))

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
            "flutter": FLUTTER_RULE_IDS["Data Storage"].get(evidence_key, frozenset()),
            "android": ANDROID_RULE_IDS["Data Storage"].get(evidence_key, frozenset()),
            "ios": IOS_STORAGE_RULE_IDS.get(evidence_key, frozenset()),
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

    @classmethod
    def _external_storage_entry(cls, context: FlutterScanExtractionContext) -> FlutterEvidenceEntry:
        if not opengrep_scope_applicable(context, "android"):
            return FlutterEvidenceEntry(None)
        permissions = context.android_metadata.get("permissions")
        if not isinstance(permissions, list):
            return FlutterEvidenceEntry(None)
        declared = {context.first_non_empty(item.get("name")) for item in permissions if isinstance(item, dict)}
        matches = sorted(declared & cls.EXTERNAL_STORAGE_PERMISSIONS)
        return FlutterEvidenceEntry(
            bool(matches),
            ", ".join(matches) if matches else "no_external_storage_permissions",
            matches,
        )
