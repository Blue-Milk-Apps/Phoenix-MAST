"""Build default iOS data evidence section."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from domain.post_scan.ios.code_evidence_builder import EvidenceEntry


@dataclass
class IOSStorageEvidence:
    deprecated_keychain_attributes: EvidenceEntry
    advertiser_id_stored_insecurely: EvidenceEntry
    imei_stored_insecurely: EvidenceEntry
    global_write_permissions: EvidenceEntry
    gps_latitude_stored_insecurely: EvidenceEntry
    gps_longitude_stored_insecurely: EvidenceEntry
    hardcoded_api_keys_stored_insecurely: EvidenceEntry
    hardcoded_passwords_stored_insecurely: EvidenceEntry
    sensitive_values_stored_insecurely: EvidenceEntry
    wifi_ip_stored_insecurely: EvidenceEntry
    wifi_mac_stored_insecurely: EvidenceEntry
    keychain_plaintext_values: EvidenceEntry
    nsuserdefaults_sensitive_values: EvidenceEntry
    advertiser_id_logged_insecurely: EvidenceEntry
    imei_logged_insecurely: EvidenceEntry
    gps_latitude_logged_insecurely: EvidenceEntry
    gps_longitude_logged_insecurely: EvidenceEntry
    sensitive_data_logged_insecurely: EvidenceEntry
    sensitive_values_in_memory: EvidenceEntry
    wifi_mac_logged_insecurely: EvidenceEntry
    keyboard_cache_exposure: EvidenceEntry

    DEPRECATED_KEYCHAIN_ATTRIBUTES = (
        "kSecAttrAccessibleAlwaysThisDeviceOnly",
        "kSecAttrAccessibleAlways",
    )
    DEPRECATED_KEYCHAIN_ATTRIBUTES_RULE_ID = "ios.storage.deprecated-keychain-accessibility"
    ADVERTISER_ID_INSECURE_STORAGE_RULE_ID = "ios.storage.advertiser-id-insecure-storage"
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

    def __init__(self, loaded_outputs: dict[str, Any]) -> None:
        self.deprecated_keychain_attributes = self._deprecated_keychain_attributes_entry(loaded_outputs)
        self.advertiser_id_stored_insecurely = self._advertiser_id_stored_insecurely_entry(loaded_outputs)
        self.imei_stored_insecurely = EvidenceEntry(False, "no_imei_stored_insecurely_hits")
        self.global_write_permissions = EvidenceEntry(False, "no_global_write_permissions_hits")
        self.gps_latitude_stored_insecurely = EvidenceEntry(False, "no_gps_latitude_stored_insecurely_hits")
        self.gps_longitude_stored_insecurely = EvidenceEntry(False, "no_gps_longitude_stored_insecurely_hits")
        self.hardcoded_api_keys_stored_insecurely = EvidenceEntry(False, "no_hardcoded_api_keys_stored_insecurely_hits")
        self.hardcoded_passwords_stored_insecurely = EvidenceEntry(
            False, "no_hardcoded_passwords_stored_insecurely_hits"
        )
        self.sensitive_values_stored_insecurely = EvidenceEntry(False, "no_sensitive_values_stored_insecurely_hits")
        self.wifi_ip_stored_insecurely = EvidenceEntry(False, "no_wifi_ip_stored_insecurely_hits")
        self.wifi_mac_stored_insecurely = EvidenceEntry(False, "no_wifi_mac_stored_insecurely_hits")
        self.keychain_plaintext_values = EvidenceEntry(False, "no_keychain_plaintext_values_hits")
        self.nsuserdefaults_sensitive_values = EvidenceEntry(False, "no_nsuserdefaults_sensitive_values_hits")
        self.advertiser_id_logged_insecurely = EvidenceEntry(False, "no_advertiser_id_logged_insecurely_hits")
        self.imei_logged_insecurely = EvidenceEntry(False, "no_imei_logged_insecurely_hits")
        self.gps_latitude_logged_insecurely = EvidenceEntry(False, "no_gps_latitude_logged_insecurely_hits")
        self.gps_longitude_logged_insecurely = EvidenceEntry(False, "no_gps_longitude_logged_insecurely_hits")
        self.sensitive_data_logged_insecurely = EvidenceEntry(False, "no_sensitive_data_logged_insecurely_hits")
        self.sensitive_values_in_memory = EvidenceEntry(False, "no_sensitive_values_in_memory_hits")
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
