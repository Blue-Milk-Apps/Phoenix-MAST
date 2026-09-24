"""Build the iOS data-storage evidence section."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from domain.post_scan.ios.common.evidence import EvidenceEntry


@dataclass
class IOSDataStorageEvidence:
    weak_file_protection: EvidenceEntry
    deprecated_keychain_attributes: EvidenceEntry
    advertiser_id_stored_insecurely: EvidenceEntry
    imei_labeled_value_stored_insecurely: EvidenceEntry
    global_write_permissions: EvidenceEntry
    location_data_stored_insecurely: EvidenceEntry
    hardcoded_api_keys_stored_insecurely: EvidenceEntry
    hardcoded_passwords_stored_insecurely: EvidenceEntry
    sensitive_values_stored_insecurely: EvidenceEntry
    wifi_ip_stored_insecurely: EvidenceEntry
    wifi_mac_stored_insecurely: EvidenceEntry
    sensitive_values_stored_in_memory: EvidenceEntry
    keychain_items_accessible_after_first_unlock: EvidenceEntry
    sensitive_data_stored_in_user_defaults: EvidenceEntry
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
    USER_DEFAULTS_MARKERS = ("UserDefaults", "NSUserDefaults", "setObject:forKey:")
    SENSITIVE_DATA_MARKERS = (
        "access_token",
        "auth_token",
        "api_key",
        "account_number",
        "credit_card",
        "password",
        "passwd",
        "token",
        "session",
        "email",
        "phone",
        "ssn",
    )
    LOGGING_MARKERS = ("nslog", "os_log", "logger", "debugprint", "print")
    LOCATION_DATA_MARKERS = ("cllocation", "coordinate", "latitude", "longitude")
    WIFI_MAC_MARKERS = ("wifi_mac", "wifimac", "mac_address", "macaddress", "bssid")
    API_KEY_MARKERS = ("api_key", "apikey", "api key")
    PASSWORD_MARKERS = ("password", "passwd", "pwd")
    WIFI_IP_MARKERS = ("wifi_ip", "wifiip", "wifi ip", "wifiipaddress")
    NON_USER_DEFAULTS_STORAGE_MARKERS = ("writeToFile:", "writeToURL:", "NSKeyedArchiver")

    def __init__(self, loaded_outputs: dict[str, Any]) -> None:
        self.weak_file_protection = self._weak_file_protection_entry(loaded_outputs)
        self.deprecated_keychain_attributes = self._deprecated_keychain_attributes_entry(loaded_outputs)
        self.advertiser_id_stored_insecurely = self._advertiser_id_stored_insecurely_entry(loaded_outputs)
        self.imei_labeled_value_stored_insecurely = self._imei_labeled_value_stored_insecurely_entry(loaded_outputs)
        self.global_write_permissions = self._global_write_permissions_entry(loaded_outputs)
        self.location_data_stored_insecurely = self._location_data_stored_insecurely_entry(loaded_outputs)
        self.hardcoded_api_keys_stored_insecurely = self._hardcoded_api_keys_stored_insecurely_entry(loaded_outputs)
        self.hardcoded_passwords_stored_insecurely = self._hardcoded_passwords_stored_insecurely_entry(loaded_outputs)
        self.sensitive_values_stored_insecurely = self._sensitive_values_stored_insecurely_entry(loaded_outputs)
        self.wifi_ip_stored_insecurely = self._wifi_ip_stored_insecurely_entry(loaded_outputs)
        self.wifi_mac_stored_insecurely = self._wifi_mac_stored_insecurely_entry(loaded_outputs)
        self.sensitive_values_stored_in_memory = self._sensitive_values_stored_in_memory_entry(loaded_outputs)
        self.keychain_items_accessible_after_first_unlock = self._keychain_items_accessible_after_first_unlock_entry(
            loaded_outputs
        )
        self.sensitive_data_stored_in_user_defaults = self._sensitive_data_stored_in_user_defaults_entry(loaded_outputs)
        self.advertiser_id_logged_insecurely = self._logged_insecurely_entry(
            loaded_outputs,
            data_markers=self.ADVERTISER_ID_MARKERS,
            no_hit_evidence="no_advertiser_id_logged_insecurely_hits",
        )
        self.imei_logged_insecurely = self._logged_insecurely_entry(
            loaded_outputs, data_markers=self.IMEI_MARKERS, no_hit_evidence="no_imei_logged_insecurely_hits"
        )
        self.location_data_logged_insecurely = self._logged_insecurely_entry(
            loaded_outputs,
            data_markers=self.LOCATION_DATA_MARKERS,
            no_hit_evidence="no_location_data_logged_insecurely_hits",
        )
        self.sensitive_data_logged_insecurely = self._logged_insecurely_entry(
            loaded_outputs,
            data_markers=self.SENSITIVE_DATA_MARKERS,
            no_hit_evidence="no_sensitive_data_logged_insecurely_hits",
        )
        self.wifi_mac_logged_insecurely = self._logged_insecurely_entry(
            loaded_outputs, data_markers=self.WIFI_MAC_MARKERS, no_hit_evidence="no_wifi_mac_logged_insecurely_hits"
        )
        self.keyboard_cache_exposure = self._keyboard_cache_exposure_entry(loaded_outputs)

    @classmethod
    def _weak_file_protection_entry(cls, loaded_outputs: dict[str, Any]) -> EvidenceEntry:
        return EvidenceEntry(None, "File-protection rule coverage is reported with the configured YAML rules.")

    @classmethod
    def _deprecated_keychain_attributes_entry(cls, loaded_outputs: dict[str, Any]) -> EvidenceEntry:
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
        strings_outputs = loaded_outputs.get("strings_outputs") or {}
        if isinstance(strings_outputs, dict):
            for path, content in strings_outputs.items():
                text = str(content or "")
                advertiser_id_marker = next((marker for marker in cls.ADVERTISER_ID_MARKERS if marker in text), "")
                storage_marker = next((marker for marker in cls.INSECURE_STORAGE_MARKERS if marker in text), "")
                if advertiser_id_marker and storage_marker:
                    return EvidenceEntry(
                        None,
                        f"(Triage Signal; source review required) {path}: {advertiser_id_marker}; {storage_marker}",
                    )
        if cls._is_binary_scan(loaded_outputs):
            return EvidenceEntry(None, "source_data_flow_analysis_required")
        return EvidenceEntry(False, "no_advertiser_id_stored_insecurely_hits")

    @classmethod
    def _imei_labeled_value_stored_insecurely_entry(cls, loaded_outputs: dict[str, Any]) -> EvidenceEntry:
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
                    return EvidenceEntry(
                        None, f"(Triage Signal; source review required) {path}: {imei_marker}; {storage_marker}"
                    )
        if cls._is_binary_scan(loaded_outputs):
            return EvidenceEntry(None, "source_data_flow_analysis_required")
        return EvidenceEntry(False, "no_imei_labeled_value_stored_insecurely_hits")

    @classmethod
    def _global_write_permissions_entry(cls, loaded_outputs: dict[str, Any]) -> EvidenceEntry:
        if cls._is_binary_scan(loaded_outputs):
            return EvidenceEntry(None, "source_permission_api_analysis_required")
        return EvidenceEntry(False, "no_global_write_permissions_hits")

    @classmethod
    def _location_data_stored_insecurely_entry(cls, loaded_outputs: dict[str, Any]) -> EvidenceEntry:
        return cls._source_or_storage_triage_entry(
            loaded_outputs,
            data_markers=cls.LOCATION_DATA_MARKERS,
            storage_markers=cls.INSECURE_STORAGE_MARKERS,
            no_hit_evidence="no_location_data_stored_insecurely_hits",
        )

    @classmethod
    def _hardcoded_api_keys_stored_insecurely_entry(cls, loaded_outputs: dict[str, Any]) -> EvidenceEntry:
        return cls._source_or_storage_triage_entry(
            loaded_outputs,
            data_markers=cls.API_KEY_MARKERS,
            storage_markers=cls.INSECURE_STORAGE_MARKERS,
            no_hit_evidence="no_hardcoded_api_keys_stored_insecurely_hits",
        )

    @classmethod
    def _hardcoded_passwords_stored_insecurely_entry(cls, loaded_outputs: dict[str, Any]) -> EvidenceEntry:
        return cls._source_or_storage_triage_entry(
            loaded_outputs,
            data_markers=cls.PASSWORD_MARKERS,
            storage_markers=cls.INSECURE_STORAGE_MARKERS,
            no_hit_evidence="no_hardcoded_passwords_stored_insecurely_hits",
        )

    @classmethod
    def _sensitive_values_stored_insecurely_entry(cls, loaded_outputs: dict[str, Any]) -> EvidenceEntry:
        return cls._source_or_storage_triage_entry(
            loaded_outputs,
            data_markers=cls.SENSITIVE_DATA_MARKERS,
            storage_markers=cls.NON_USER_DEFAULTS_STORAGE_MARKERS,
            no_hit_evidence="no_sensitive_values_stored_insecurely_hits",
        )

    @classmethod
    def _wifi_ip_stored_insecurely_entry(cls, loaded_outputs: dict[str, Any]) -> EvidenceEntry:
        return cls._source_or_storage_triage_entry(
            loaded_outputs,
            data_markers=cls.WIFI_IP_MARKERS,
            storage_markers=cls.INSECURE_STORAGE_MARKERS,
            no_hit_evidence="no_wifi_ip_stored_insecurely_hits",
        )

    @classmethod
    def _wifi_mac_stored_insecurely_entry(cls, loaded_outputs: dict[str, Any]) -> EvidenceEntry:
        return EvidenceEntry(None, "source_data_flow_analysis_required")

    @classmethod
    def _sensitive_values_stored_in_memory_entry(cls, loaded_outputs: dict[str, Any]) -> EvidenceEntry:
        return EvidenceEntry(None, "dynamic_memory_analysis_required")

    @classmethod
    def _source_or_storage_triage_entry(
        cls,
        loaded_outputs: dict[str, Any],
        *,
        data_markers: tuple[str, ...],
        storage_markers: tuple[str, ...],
        no_hit_evidence: str,
    ) -> EvidenceEntry:
        strings_outputs = loaded_outputs.get("strings_outputs") or {}
        if isinstance(strings_outputs, dict):
            for path, content in strings_outputs.items():
                text = str(content or "")
                lowered_text = text.lower()
                data_marker = next(
                    (
                        marker
                        for marker in sorted(data_markers, key=len, reverse=True)
                        if marker.lower() in lowered_text
                    ),
                    "",
                )
                storage_marker = next((marker for marker in storage_markers if marker.lower() in lowered_text), "")
                if data_marker and storage_marker:
                    return EvidenceEntry(
                        None, f"(Triage Signal; source review required) {path}: {data_marker}; {storage_marker}"
                    )
        if cls._is_binary_scan(loaded_outputs):
            return EvidenceEntry(None, "source_data_flow_analysis_required")
        return EvidenceEntry(False, no_hit_evidence)

    @classmethod
    def _sensitive_data_stored_in_user_defaults_entry(cls, loaded_outputs: dict[str, Any]) -> EvidenceEntry:
        strings_outputs = loaded_outputs.get("strings_outputs") or {}
        if isinstance(strings_outputs, dict):
            for path, content in strings_outputs.items():
                text = str(content or "")
                lowered_text = text.lower()
                user_defaults_marker = next((marker for marker in cls.USER_DEFAULTS_MARKERS if marker in text), "")
                sensitive_marker = next((marker for marker in cls.SENSITIVE_DATA_MARKERS if marker in lowered_text), "")
                if user_defaults_marker and sensitive_marker:
                    return EvidenceEntry(
                        None,
                        f"(Triage Signal; source review required) {path}: {user_defaults_marker}; {sensitive_marker}",
                    )
        if cls._is_binary_scan(loaded_outputs):
            return EvidenceEntry(None, "source_data_flow_analysis_required")
        return EvidenceEntry(False, "no_sensitive_data_stored_in_user_defaults_hits")

    @classmethod
    def _logged_insecurely_entry(
        cls, loaded_outputs: dict[str, Any], *, data_markers: tuple[str, ...], no_hit_evidence: str
    ) -> EvidenceEntry:
        strings_outputs = loaded_outputs.get("strings_outputs") or {}
        if isinstance(strings_outputs, dict):
            for path, content in strings_outputs.items():
                text = str(content or "")
                lowered_text = text.lower()
                logging_marker = next((marker for marker in cls.LOGGING_MARKERS if marker in lowered_text), "")
                data_marker = next(
                    (
                        marker
                        for marker in sorted(data_markers, key=len, reverse=True)
                        if marker.lower() in lowered_text
                    ),
                    "",
                )
                if logging_marker and data_marker:
                    return EvidenceEntry(
                        None, f"(Triage Signal; source review required) {path}: {logging_marker}; {data_marker}"
                    )
        if cls._is_binary_scan(loaded_outputs):
            return EvidenceEntry(None, "source_data_flow_analysis_required")
        return EvidenceEntry(False, no_hit_evidence)

    @classmethod
    def _keyboard_cache_exposure_entry(cls, loaded_outputs: dict[str, Any]) -> EvidenceEntry:
        if cls._is_binary_scan(loaded_outputs):
            return EvidenceEntry(None, "source_input_configuration_analysis_required")
        return EvidenceEntry(False, "no_keyboard_cache_exposure_hits")

    @staticmethod
    def _is_binary_scan(loaded_outputs: dict[str, Any]) -> bool:
        """Identify binary output so strings-only signals are not reported as confirmed findings."""

        metadata = loaded_outputs.get("scan_metadata")
        if isinstance(metadata, dict):
            target_type = str(metadata.get("target_type") or "").strip().lower()
            if target_type == "binary":
                return True
            target_kind = str(metadata.get("target_kind") or "").strip().lower()
            if target_kind.endswith("_binary"):
                return True
        return any(key in loaded_outputs for key in ("strings_outputs", "ipsw_outputs", "lief_outputs"))
