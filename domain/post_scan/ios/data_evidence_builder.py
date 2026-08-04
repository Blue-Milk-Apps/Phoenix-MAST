"""Build default iOS data evidence section."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from domain.post_scan.ios.code_evidence_builder import EvidenceEntry

# TODO(dynamic): Add sensitive-values-in-memory evidence when runtime memory inspection is available.
# It is intentionally omitted from static scan results.


@dataclass
class IOSStorageEvidence:
    deprecated_keychain_attributes: EvidenceEntry
    advertiser_id_stored_insecurely: EvidenceEntry
    imei_labeled_value_stored_insecurely: EvidenceEntry
    global_write_permissions: EvidenceEntry
    location_data_stored_insecurely: EvidenceEntry
    hardcoded_api_keys_stored_insecurely: EvidenceEntry
    hardcoded_passwords_stored_insecurely: EvidenceEntry
    sensitive_values_stored_insecurely: EvidenceEntry
    wifi_ip_stored_insecurely: EvidenceEntry
    keychain_items_accessible_after_first_unlock: EvidenceEntry
    nsuserdefaults_sensitive_values: EvidenceEntry
    advertiser_id_logged_insecurely: EvidenceEntry
    imei_logged_insecurely: EvidenceEntry
    location_data_logged_insecurely: EvidenceEntry
    sensitive_data_logged_insecurely: EvidenceEntry
    wifi_mac_logged_insecurely: EvidenceEntry
    keyboard_cache_exposure: EvidenceEntry

    DEPRECATED_KEYCHAIN_ATTRIBUTES = (
        "kSecAttrAccessibleAlwaysThisDeviceOnly",
        "kSecAttrAccessibleAlways",
    )
    KEYCHAIN_ACCESSIBILITY_REVIEW_ATTRIBUTES = (
        "kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly",
        "kSecAttrAccessibleAfterFirstUnlock",
    )
    DEPRECATED_KEYCHAIN_ATTRIBUTES_RULE_ID = "ios.storage.deprecated-keychain-accessibility"
    KEYCHAIN_ITEMS_ACCESSIBLE_AFTER_FIRST_UNLOCK_RULE_ID = "ios.storage.keychain-items-accessible-after-first-unlock"
    ADVERTISER_ID_INSECURE_STORAGE_RULE_ID = "ios.storage.advertiser-id-insecure-storage"
    IMEI_LABELED_VALUE_INSECURE_STORAGE_RULE_ID = "ios.storage.imei-labeled-value-insecure-storage"
    GLOBAL_WRITE_PERMISSIONS_RULE_ID = "ios.storage.global-write-permissions"
    LOCATION_DATA_INSECURE_STORAGE_RULE_ID = "ios.storage.location-data-insecure-storage"
    HARDCODED_API_KEY_INSECURE_STORAGE_RULE_ID = "ios.storage.hardcoded-api-key-insecure-storage"
    HARDCODED_PASSWORD_INSECURE_STORAGE_RULE_ID = "ios.storage.hardcoded-password-insecure-storage"
    SENSITIVE_VALUE_INSECURE_STORAGE_RULE_ID = "ios.storage.sensitive-value-insecure-storage"
    WIFI_IP_INSECURE_STORAGE_RULE_ID = "ios.storage.wifi-ip-insecure-storage"
    ADVERTISER_ID_MARKERS = (
        "ASIdentifierManager",
        "advertisingIdentifier",
        "idfa",
    )
    INSECURE_STORAGE_MARKERS = (
        "UserDefaults",
        "setObject:forKey:",
        "writeToFile:",
        "writeToURL:",
        "NSKeyedArchiver",
    )
    IMEI_MARKERS = ("imei", "deviceImei", "device_imei")

    def __init__(self, loaded_outputs: dict[str, Any]) -> None:
        self.deprecated_keychain_attributes = self._deprecated_keychain_attributes_entry(loaded_outputs)
        self.advertiser_id_stored_insecurely = self._advertiser_id_stored_insecurely_entry(loaded_outputs)
        self.imei_labeled_value_stored_insecurely = self._imei_labeled_value_stored_insecurely_entry(loaded_outputs)
        self.global_write_permissions = self._global_write_permissions_entry(loaded_outputs)
        self.location_data_stored_insecurely = self._location_data_stored_insecurely_entry(loaded_outputs)
        self.hardcoded_api_keys_stored_insecurely = self._hardcoded_api_keys_stored_insecurely_entry(loaded_outputs)
        self.hardcoded_passwords_stored_insecurely = self._hardcoded_passwords_stored_insecurely_entry(loaded_outputs)
        self.sensitive_values_stored_insecurely = self._sensitive_values_stored_insecurely_entry(loaded_outputs)
        self.wifi_ip_stored_insecurely = self._wifi_ip_stored_insecurely_entry(loaded_outputs)
        self.keychain_items_accessible_after_first_unlock = self._keychain_items_accessible_after_first_unlock_entry(
            loaded_outputs
        )
        self.nsuserdefaults_sensitive_values = EvidenceEntry(False, "no_nsuserdefaults_sensitive_values_hits")
        self.advertiser_id_logged_insecurely = EvidenceEntry(False, "no_advertiser_id_logged_insecurely_hits")
        self.imei_logged_insecurely = EvidenceEntry(False, "no_imei_logged_insecurely_hits")
        self.location_data_logged_insecurely = EvidenceEntry(False, "no_location_data_logged_insecurely_hits")
        self.sensitive_data_logged_insecurely = EvidenceEntry(False, "no_sensitive_data_logged_insecurely_hits")
        self.wifi_mac_logged_insecurely = EvidenceEntry(False, "no_wifi_mac_logged_insecurely_hits")
        self.keyboard_cache_exposure = EvidenceEntry(False, "no_keyboard_cache_exposure_hits")

    @classmethod
    def _deprecated_keychain_attributes_entry(cls, loaded_outputs: dict[str, Any]) -> EvidenceEntry:
        for result in (loaded_outputs.get("opengrep") or {}).get("results") or []:
            if not isinstance(result, dict) or result.get("check_id") != cls.DEPRECATED_KEYCHAIN_ATTRIBUTES_RULE_ID:
                continue
            extra = result.get("extra") or {}
            evidence = str(extra.get("lines") or extra.get("message") or result.get("check_id")).strip()
            path = str(result.get("path", "")).strip()
            return EvidenceEntry(True, f"{path}: {evidence}" if path else evidence)

        strings_outputs = loaded_outputs.get("strings_outputs") or {}
        if isinstance(strings_outputs, dict):
            for path, content in strings_outputs.items():
                text = str(content or "")
                for attribute in cls.DEPRECATED_KEYCHAIN_ATTRIBUTES:
                    if attribute in text:
                        return EvidenceEntry(True, f"{path}: {attribute}")

        return EvidenceEntry(False, "no_deprecated_keychain_attributes_hits")

    @classmethod
    def _keychain_items_accessible_after_first_unlock_entry(cls, loaded_outputs: dict[str, Any]) -> EvidenceEntry:
        for result in (loaded_outputs.get("opengrep") or {}).get("results") or []:
            if (
                not isinstance(result, dict)
                or result.get("check_id") != cls.KEYCHAIN_ITEMS_ACCESSIBLE_AFTER_FIRST_UNLOCK_RULE_ID
            ):
                continue
            extra = result.get("extra") or {}
            evidence = str(extra.get("lines") or extra.get("message") or result.get("check_id")).strip()
            path = str(result.get("path", "")).strip()
            return EvidenceEntry(True, f"{path}: {evidence}" if path else evidence)

        strings_outputs = loaded_outputs.get("strings_outputs") or {}
        if isinstance(strings_outputs, dict):
            for path, content in strings_outputs.items():
                text = str(content or "")
                for attribute in cls.KEYCHAIN_ACCESSIBILITY_REVIEW_ATTRIBUTES:
                    if attribute in text:
                        return EvidenceEntry(True, f"{path}: {attribute}")

        return EvidenceEntry(False, "no_keychain_items_accessible_after_first_unlock_hits")

    @classmethod
    def _advertiser_id_stored_insecurely_entry(cls, loaded_outputs: dict[str, Any]) -> EvidenceEntry:
        for result in (loaded_outputs.get("opengrep") or {}).get("results") or []:
            if not isinstance(result, dict) or result.get("check_id") != cls.ADVERTISER_ID_INSECURE_STORAGE_RULE_ID:
                continue
            extra = result.get("extra") or {}
            evidence = str(extra.get("lines") or extra.get("message") or result.get("check_id")).strip()
            path = str(result.get("path", "")).strip()
            return EvidenceEntry(True, f"{path}: {evidence}" if path else evidence)

        strings_outputs = loaded_outputs.get("strings_outputs") or {}
        if isinstance(strings_outputs, dict):
            for path, content in strings_outputs.items():
                text = str(content or "")
                advertiser_id_marker = next((marker for marker in cls.ADVERTISER_ID_MARKERS if marker in text), "")
                storage_marker = next((marker for marker in cls.INSECURE_STORAGE_MARKERS if marker in text), "")
                if advertiser_id_marker and storage_marker:
                    return EvidenceEntry(True, f"{path}: {advertiser_id_marker}; {storage_marker}")

        return EvidenceEntry(False, "no_advertiser_id_stored_insecurely_hits")

    @classmethod
    def _imei_labeled_value_stored_insecurely_entry(cls, loaded_outputs: dict[str, Any]) -> EvidenceEntry:
        for result in (loaded_outputs.get("opengrep") or {}).get("results") or []:
            if (
                not isinstance(result, dict)
                or result.get("check_id") != cls.IMEI_LABELED_VALUE_INSECURE_STORAGE_RULE_ID
            ):
                continue
            extra = result.get("extra") or {}
            evidence = str(extra.get("lines") or extra.get("message") or result.get("check_id")).strip()
            path = str(result.get("path", "")).strip()
            return EvidenceEntry(True, f"{path}: {evidence}" if path else evidence)

        strings_outputs = loaded_outputs.get("strings_outputs") or {}
        if isinstance(strings_outputs, dict):
            for path, content in strings_outputs.items():
                text = str(content or "")
                lowered_text = text.lower()
                imei_marker = next(
                    (
                        marker
                        for marker in sorted(cls.IMEI_MARKERS, key=len, reverse=True)
                        if marker.lower() in lowered_text
                    ),
                    "",
                )
                storage_marker = next((marker for marker in cls.INSECURE_STORAGE_MARKERS if marker in text), "")
                if imei_marker and storage_marker:
                    return EvidenceEntry(True, f"{path}: {imei_marker}; {storage_marker}")

        return EvidenceEntry(False, "no_imei_labeled_value_stored_insecurely_hits")

    @classmethod
    def _global_write_permissions_entry(cls, loaded_outputs: dict[str, Any]) -> EvidenceEntry:
        # Source-focused: binary strings cannot prove a permission-setting call grants global write access.
        opengrep = loaded_outputs.get("opengrep")
        results = opengrep.get("results") if isinstance(opengrep, dict) else None
        if not isinstance(results, list):
            return EvidenceEntry(False, "global_write_permissions_not_assessed_no_opengrep_results")

        for result in results:
            if not isinstance(result, dict) or result.get("check_id") != cls.GLOBAL_WRITE_PERMISSIONS_RULE_ID:
                continue
            extra = result.get("extra") or {}
            evidence = str(extra.get("lines") or extra.get("message") or result.get("check_id")).strip()
            path = str(result.get("path", "")).strip()
            return EvidenceEntry(True, f"{path}: {evidence}" if path else evidence)

        return EvidenceEntry(False, "no_global_write_permissions_hits")

    @classmethod
    def _location_data_stored_insecurely_entry(cls, loaded_outputs: dict[str, Any]) -> EvidenceEntry:
        opengrep = loaded_outputs.get("opengrep")
        results = opengrep.get("results") if isinstance(opengrep, dict) else None
        if not isinstance(results, list):
            return EvidenceEntry(False, "location_data_stored_insecurely_not_assessed_binary_scan")

        for result in results:
            if not isinstance(result, dict) or result.get("check_id") != cls.LOCATION_DATA_INSECURE_STORAGE_RULE_ID:
                continue
            extra = result.get("extra") or {}
            evidence = str(extra.get("lines") or extra.get("message") or result.get("check_id")).strip()
            path = str(result.get("path", "")).strip()
            return EvidenceEntry(True, f"{path}: {evidence}" if path else evidence)

        return EvidenceEntry(False, "no_location_data_stored_insecurely_hits")

    @classmethod
    def _hardcoded_api_keys_stored_insecurely_entry(cls, loaded_outputs: dict[str, Any]) -> EvidenceEntry:
        opengrep = loaded_outputs.get("opengrep")
        results = opengrep.get("results") if isinstance(opengrep, dict) else None
        if not isinstance(results, list):
            return EvidenceEntry(False, "hardcoded_api_keys_stored_insecurely_not_assessed_binary_scan")

        for result in results:
            if not isinstance(result, dict) or result.get("check_id") != cls.HARDCODED_API_KEY_INSECURE_STORAGE_RULE_ID:
                continue
            extra = result.get("extra") or {}
            evidence = str(extra.get("lines") or extra.get("message") or result.get("check_id")).strip()
            path = str(result.get("path", "")).strip()
            return EvidenceEntry(True, f"{path}: {evidence}" if path else evidence)

        return EvidenceEntry(False, "no_hardcoded_api_keys_stored_insecurely_hits")

    @classmethod
    def _hardcoded_passwords_stored_insecurely_entry(cls, loaded_outputs: dict[str, Any]) -> EvidenceEntry:
        opengrep = loaded_outputs.get("opengrep")
        results = opengrep.get("results") if isinstance(opengrep, dict) else None
        if not isinstance(results, list):
            return EvidenceEntry(False, "hardcoded_passwords_stored_insecurely_not_assessed_binary_scan")

        for result in results:
            if (
                not isinstance(result, dict)
                or result.get("check_id") != cls.HARDCODED_PASSWORD_INSECURE_STORAGE_RULE_ID
            ):
                continue
            extra = result.get("extra") or {}
            evidence = str(extra.get("lines") or extra.get("message") or result.get("check_id")).strip()
            path = str(result.get("path", "")).strip()
            return EvidenceEntry(True, f"{path}: {evidence}" if path else evidence)

        return EvidenceEntry(False, "no_hardcoded_passwords_stored_insecurely_hits")

    @classmethod
    def _sensitive_values_stored_insecurely_entry(cls, loaded_outputs: dict[str, Any]) -> EvidenceEntry:
        opengrep = loaded_outputs.get("opengrep")
        results = opengrep.get("results") if isinstance(opengrep, dict) else None
        if not isinstance(results, list):
            return EvidenceEntry(False, "sensitive_values_stored_insecurely_not_assessed_binary_scan")

        for result in results:
            if not isinstance(result, dict) or result.get("check_id") != cls.SENSITIVE_VALUE_INSECURE_STORAGE_RULE_ID:
                continue
            extra = result.get("extra") or {}
            evidence = str(extra.get("lines") or extra.get("message") or result.get("check_id")).strip()
            path = str(result.get("path", "")).strip()
            return EvidenceEntry(True, f"{path}: {evidence}" if path else evidence)

        return EvidenceEntry(False, "no_sensitive_values_stored_insecurely_hits")

    @classmethod
    def _wifi_ip_stored_insecurely_entry(cls, loaded_outputs: dict[str, Any]) -> EvidenceEntry:
        opengrep = loaded_outputs.get("opengrep")
        results = opengrep.get("results") if isinstance(opengrep, dict) else None
        if not isinstance(results, list):
            return EvidenceEntry(False, "wifi_ip_stored_insecurely_not_assessed_binary_scan")

        for result in results:
            if not isinstance(result, dict) or result.get("check_id") != cls.WIFI_IP_INSECURE_STORAGE_RULE_ID:
                continue
            extra = result.get("extra") or {}
            evidence = str(extra.get("lines") or extra.get("message") or result.get("check_id")).strip()
            path = str(result.get("path", "")).strip()
            return EvidenceEntry(True, f"{path}: {evidence}" if path else evidence)

        return EvidenceEntry(False, "no_wifi_ip_stored_insecurely_hits")
