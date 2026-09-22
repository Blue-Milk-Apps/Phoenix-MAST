"""Build the iOS data-storage evidence section."""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from domain.post_scan.ios.common.evidence import EvidenceEntry
from domain.post_scan.ios.rule_registry import (
    COMPLETE_FILE_PROTECTION_RULE_IDS as REGISTERED_COMPLETE_FILE_PROTECTION_RULE_IDS,
)
from domain.post_scan.ios.rule_registry import DATA_STORAGE_RULE_ID_BY_EVIDENCE_KEY
from domain.post_scan.ios.rule_registry import WEAK_FILE_PROTECTION_RULE_IDS as REGISTERED_WEAK_FILE_PROTECTION_RULE_IDS


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
    DEPRECATED_KEYCHAIN_ATTRIBUTES_RULE_ID = DATA_STORAGE_RULE_ID_BY_EVIDENCE_KEY["deprecated_keychain_attributes"]
    KEYCHAIN_ITEMS_ACCESSIBLE_AFTER_FIRST_UNLOCK_RULE_ID = DATA_STORAGE_RULE_ID_BY_EVIDENCE_KEY[
        "keychain_items_accessible_after_first_unlock"
    ]
    ADVERTISER_ID_INSECURE_STORAGE_RULE_ID = DATA_STORAGE_RULE_ID_BY_EVIDENCE_KEY["advertiser_id_stored_insecurely"]
    IMEI_LABELED_VALUE_INSECURE_STORAGE_RULE_ID = DATA_STORAGE_RULE_ID_BY_EVIDENCE_KEY[
        "imei_labeled_value_stored_insecurely"
    ]
    GLOBAL_WRITE_PERMISSIONS_RULE_ID = DATA_STORAGE_RULE_ID_BY_EVIDENCE_KEY["global_write_permissions"]
    LOCATION_DATA_INSECURE_STORAGE_RULE_ID = DATA_STORAGE_RULE_ID_BY_EVIDENCE_KEY["location_data_stored_insecurely"]
    HARDCODED_API_KEY_INSECURE_STORAGE_RULE_ID = DATA_STORAGE_RULE_ID_BY_EVIDENCE_KEY[
        "hardcoded_api_keys_stored_insecurely"
    ]
    HARDCODED_PASSWORD_INSECURE_STORAGE_RULE_ID = DATA_STORAGE_RULE_ID_BY_EVIDENCE_KEY[
        "hardcoded_passwords_stored_insecurely"
    ]
    SENSITIVE_VALUE_INSECURE_STORAGE_RULE_ID = DATA_STORAGE_RULE_ID_BY_EVIDENCE_KEY[
        "sensitive_values_stored_insecurely"
    ]
    SENSITIVE_DATA_IN_USER_DEFAULTS_RULE_ID = DATA_STORAGE_RULE_ID_BY_EVIDENCE_KEY[
        "sensitive_data_stored_in_user_defaults"
    ]
    WIFI_IP_INSECURE_STORAGE_RULE_ID = DATA_STORAGE_RULE_ID_BY_EVIDENCE_KEY["wifi_ip_stored_insecurely"]
    WIFI_MAC_INSECURE_STORAGE_RULE_ID = DATA_STORAGE_RULE_ID_BY_EVIDENCE_KEY["wifi_mac_stored_insecurely"]
    SENSITIVE_VALUE_LONG_LIVED_MEMORY_RULE_ID = "ios.storage.sensitive-value-long-lived-memory"
    ADVERTISER_ID_LOGGING_RULE_ID = DATA_STORAGE_RULE_ID_BY_EVIDENCE_KEY["advertiser_id_logged_insecurely"]
    IMEI_LOGGING_RULE_ID = DATA_STORAGE_RULE_ID_BY_EVIDENCE_KEY["imei_logged_insecurely"]
    LOCATION_DATA_LOGGING_RULE_ID = DATA_STORAGE_RULE_ID_BY_EVIDENCE_KEY["location_data_logged_insecurely"]
    SENSITIVE_DATA_LOGGING_RULE_ID = DATA_STORAGE_RULE_ID_BY_EVIDENCE_KEY["sensitive_data_logged_insecurely"]
    WIFI_MAC_LOGGING_RULE_ID = DATA_STORAGE_RULE_ID_BY_EVIDENCE_KEY["wifi_mac_logged_insecurely"]
    KEYBOARD_CACHE_EXPOSURE_RULE_ID = DATA_STORAGE_RULE_ID_BY_EVIDENCE_KEY["keyboard_cache_exposure"]
    WEAK_FILE_PROTECTION_RULE_IDS = REGISTERED_WEAK_FILE_PROTECTION_RULE_IDS
    COMPLETE_FILE_PROTECTION_RULE_IDS = REGISTERED_COMPLETE_FILE_PROTECTION_RULE_IDS
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

    @classmethod
    def _opengrep_evidence(
        cls,
        result: dict[str, Any],
        loaded_outputs: dict[str, Any] | None = None,
        *,
        include_operation: bool = False,
        include_dataflow: bool = False,
    ) -> str:
        """Return matched source evidence with a location when OpenGrep provides one."""

        extra = result.get("extra") or {}
        evidence = str(extra.get("lines") or extra.get("message") or result.get("check_id")).strip()
        path = str(result.get("path", "")).strip()
        start = result.get("start")
        line = start.get("line") if isinstance(start, dict) else None
        if path and line not in (None, ""):
            path = f"{path}:{line}"
        elif not path and line not in (None, ""):
            path = f"line {line}"
        formatted = f"{path}: {evidence}" if path else evidence
        if include_operation:
            operation = cls._keychain_operation(result, loaded_outputs or {})
            if operation and operation not in evidence:
                formatted = f"{formatted} (Keychain operation: {operation})"
        if include_dataflow:
            dataflow = cls._dataflow_context(result)
            if dataflow:
                formatted = f"{formatted} (Data flow: {dataflow})"
        return formatted

    @classmethod
    def _keychain_operation(cls, result: dict[str, Any], loaded_outputs: dict[str, Any]) -> str:
        """Find a nearby Keychain API name without copying surrounding source values."""

        lines = str((result.get("extra") or {}).get("lines") or "")
        operation_pattern = re.compile(r"\bSecItem(?:Add|Update|CopyMatching|Delete)\b")
        match = operation_pattern.search(lines)
        if match:
            return match.group(0)

        path_text = str(result.get("path") or "").strip()
        start = result.get("start")
        line_number = start.get("line") if isinstance(start, dict) else None
        project_text = str((loaded_outputs.get("scan_metadata") or {}).get("project_path") or "").strip()
        if not path_text or not project_text or not isinstance(line_number, int):
            return ""
        path = Path(path_text)
        project = Path(project_text)
        if not path.is_absolute():
            path = project / path
        try:
            path = path.resolve()
            path.relative_to(project.resolve())
        except (OSError, ValueError):
            return ""
        if not path.is_file():
            return ""
        try:
            source_lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()
        except OSError:
            return ""
        nearby = source_lines[max(0, line_number - 3) : min(len(source_lines), line_number + 2)]
        operations = []
        for source_line in nearby:
            operations.extend(operation_pattern.findall(source_line))
        return next(iter(dict.fromkeys(operations)), "")

    @staticmethod
    def _dataflow_context(result: dict[str, Any]) -> str:
        """Summarize taint endpoints and intermediate identifiers without values."""

        trace = result.get("dataflow_trace")
        if not isinstance(trace, dict):
            return ""

        def content_from_metavar(name: str) -> str:
            metavars = (result.get("extra") or {}).get("metavars")
            item = metavars.get(name) if isinstance(metavars, dict) else None
            content = item.get("abstract_content") if isinstance(item, dict) else None
            return str(content or "").strip()

        def safe_identifier(value: str) -> str:
            return value if re.fullmatch(r"[A-Za-z_]\w*", value) else "<value>"

        source = content_from_metavar("$VALUE")
        intermediate = [
            str(item.get("content") or "").strip()
            for item in trace.get("intermediate_vars", [])
            if isinstance(item, dict) and str(item.get("content") or "").strip()
        ]
        sink = trace.get("taint_sink")
        sink_content = ""
        if isinstance(sink, list) and len(sink) > 1 and isinstance(sink[1], list) and len(sink[1]) > 1:
            sink_content = str(sink[1][1] or "").strip()
        if not sink_content:
            return ""
        sink_api = re.match(
            r"\s*((?:UserDefaults|NSKeyedArchiver)(?:\.[A-Za-z_]\w*)+|[A-Za-z_]\w*\.write(?:ToFile|ToURL)?)",
            sink_content,
        )
        sink_name = sink_api.group(1) if sink_api else "storage API"
        identifiers = [safe_identifier(item) for item in ([source, *intermediate]) if item]
        return " -> ".join([*identifiers, sink_name]) if identifiers else sink_name

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
            rule_id=self.ADVERTISER_ID_LOGGING_RULE_ID,
            data_markers=self.ADVERTISER_ID_MARKERS,
            no_hit_evidence="no_advertiser_id_logged_insecurely_hits",
        )
        self.imei_logged_insecurely = self._logged_insecurely_entry(
            loaded_outputs,
            rule_id=self.IMEI_LOGGING_RULE_ID,
            data_markers=self.IMEI_MARKERS,
            no_hit_evidence="no_imei_logged_insecurely_hits",
        )
        self.location_data_logged_insecurely = self._logged_insecurely_entry(
            loaded_outputs,
            rule_id=self.LOCATION_DATA_LOGGING_RULE_ID,
            data_markers=self.LOCATION_DATA_MARKERS,
            no_hit_evidence="no_location_data_logged_insecurely_hits",
        )
        self.sensitive_data_logged_insecurely = self._logged_insecurely_entry(
            loaded_outputs,
            rule_id=self.SENSITIVE_DATA_LOGGING_RULE_ID,
            data_markers=self.SENSITIVE_DATA_MARKERS,
            no_hit_evidence="no_sensitive_data_logged_insecurely_hits",
        )
        self.wifi_mac_logged_insecurely = self._logged_insecurely_entry(
            loaded_outputs,
            rule_id=self.WIFI_MAC_LOGGING_RULE_ID,
            data_markers=self.WIFI_MAC_MARKERS,
            no_hit_evidence="no_wifi_mac_logged_insecurely_hits",
        )
        self.keyboard_cache_exposure = self._keyboard_cache_exposure_entry(loaded_outputs)

    @classmethod
    def _weak_file_protection_entry(cls, loaded_outputs: dict[str, Any]) -> EvidenceEntry:
        weak_evidence: list[str] = []
        complete_evidence: list[str] = []
        for result in (loaded_outputs.get("opengrep") or {}).get("results") or []:
            if not isinstance(result, dict):
                continue
            rule_id = str(result.get("check_id", "")).strip()
            if rule_id not in cls.WEAK_FILE_PROTECTION_RULE_IDS | cls.COMPLETE_FILE_PROTECTION_RULE_IDS:
                continue
            extra = result.get("extra") or {}
            matched_text = str(extra.get("lines") or extra.get("message") or rule_id).strip()
            path = str(result.get("path", "")).strip()
            evidence = f"{rule_id}: {matched_text}"
            if path:
                evidence = f"{path}: {evidence}"
            if rule_id in cls.WEAK_FILE_PROTECTION_RULE_IDS:
                weak_evidence.append(evidence)
            else:
                complete_evidence.append(evidence)

        if weak_evidence:
            evidence = weak_evidence + [f"complete protection also observed: {item}" for item in complete_evidence]
            return EvidenceEntry(True, "\n".join(dict.fromkeys(evidence)))
        if complete_evidence:
            return EvidenceEntry(False, "\n".join(dict.fromkeys(complete_evidence)))
        return EvidenceEntry(False, "no_file_protection_configuration_hits")

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
            return EvidenceEntry(True, cls._opengrep_evidence(result, loaded_outputs, include_operation=True))

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
        return cls._source_or_storage_triage_entry(
            loaded_outputs,
            rule_id=cls.LOCATION_DATA_INSECURE_STORAGE_RULE_ID,
            data_markers=cls.LOCATION_DATA_MARKERS,
            storage_markers=cls.INSECURE_STORAGE_MARKERS,
            no_hit_evidence="no_location_data_stored_insecurely_hits",
        )

    @classmethod
    def _hardcoded_api_keys_stored_insecurely_entry(cls, loaded_outputs: dict[str, Any]) -> EvidenceEntry:
        return cls._source_or_storage_triage_entry(
            loaded_outputs,
            rule_id=cls.HARDCODED_API_KEY_INSECURE_STORAGE_RULE_ID,
            data_markers=cls.API_KEY_MARKERS,
            storage_markers=cls.INSECURE_STORAGE_MARKERS,
            no_hit_evidence="no_hardcoded_api_keys_stored_insecurely_hits",
        )

    @classmethod
    def _hardcoded_passwords_stored_insecurely_entry(cls, loaded_outputs: dict[str, Any]) -> EvidenceEntry:
        return cls._source_or_storage_triage_entry(
            loaded_outputs,
            rule_id=cls.HARDCODED_PASSWORD_INSECURE_STORAGE_RULE_ID,
            data_markers=cls.PASSWORD_MARKERS,
            storage_markers=cls.INSECURE_STORAGE_MARKERS,
            no_hit_evidence="no_hardcoded_passwords_stored_insecurely_hits",
        )

    @classmethod
    def _sensitive_values_stored_insecurely_entry(cls, loaded_outputs: dict[str, Any]) -> EvidenceEntry:
        return cls._source_or_storage_triage_entry(
            loaded_outputs,
            rule_id=cls.SENSITIVE_VALUE_INSECURE_STORAGE_RULE_ID,
            data_markers=cls.SENSITIVE_DATA_MARKERS,
            storage_markers=cls.NON_USER_DEFAULTS_STORAGE_MARKERS,
            no_hit_evidence="no_sensitive_values_stored_insecurely_hits",
        )

    @classmethod
    def _wifi_ip_stored_insecurely_entry(cls, loaded_outputs: dict[str, Any]) -> EvidenceEntry:
        return cls._source_or_storage_triage_entry(
            loaded_outputs,
            rule_id=cls.WIFI_IP_INSECURE_STORAGE_RULE_ID,
            data_markers=cls.WIFI_IP_MARKERS,
            storage_markers=cls.INSECURE_STORAGE_MARKERS,
            no_hit_evidence="no_wifi_ip_stored_insecurely_hits",
        )

    @classmethod
    def _wifi_mac_stored_insecurely_entry(cls, loaded_outputs: dict[str, Any]) -> EvidenceEntry:
        opengrep = loaded_outputs.get("opengrep")
        results = opengrep.get("results") if isinstance(opengrep, dict) else None
        if isinstance(results, list):
            for result in results:
                if not isinstance(result, dict) or result.get("check_id") != cls.WIFI_MAC_INSECURE_STORAGE_RULE_ID:
                    continue
                return EvidenceEntry(
                    True,
                    cls._opengrep_evidence(result, loaded_outputs, include_dataflow=True),
                )
            return EvidenceEntry(False, "no_wifi_mac_stored_insecurely_hits")

        return EvidenceEntry(None, "source_data_flow_analysis_required")

    @classmethod
    def _sensitive_values_stored_in_memory_entry(cls, loaded_outputs: dict[str, Any]) -> EvidenceEntry:
        for result in (loaded_outputs.get("opengrep") or {}).get("results") or []:
            if not isinstance(result, dict) or result.get("check_id") != cls.SENSITIVE_VALUE_LONG_LIVED_MEMORY_RULE_ID:
                continue
            return EvidenceEntry(None, cls._opengrep_evidence(result))
        return EvidenceEntry(None, "dynamic_memory_analysis_required")

    @classmethod
    def _source_or_storage_triage_entry(
        cls,
        loaded_outputs: dict[str, Any],
        *,
        rule_id: str,
        data_markers: tuple[str, ...],
        storage_markers: tuple[str, ...],
        no_hit_evidence: str,
    ) -> EvidenceEntry:
        opengrep = loaded_outputs.get("opengrep")
        results = opengrep.get("results") if isinstance(opengrep, dict) else None
        if isinstance(results, list):
            for result in results:
                if not isinstance(result, dict) or result.get("check_id") != rule_id:
                    continue
                extra = result.get("extra") or {}
                evidence = str(extra.get("lines") or extra.get("message") or result.get("check_id")).strip()
                path = str(result.get("path", "")).strip()
                return EvidenceEntry(True, f"{path}: {evidence}" if path else evidence)

            return EvidenceEntry(False, no_hit_evidence)

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
                    return EvidenceEntry(True, f"(Triage Signal) {path}: {data_marker}; {storage_marker}")

        return EvidenceEntry(False, no_hit_evidence)

    @classmethod
    def _sensitive_data_stored_in_user_defaults_entry(cls, loaded_outputs: dict[str, Any]) -> EvidenceEntry:
        opengrep = loaded_outputs.get("opengrep")
        results = opengrep.get("results") if isinstance(opengrep, dict) else None
        if isinstance(results, list):
            for result in results:
                if (
                    not isinstance(result, dict)
                    or result.get("check_id") != cls.SENSITIVE_DATA_IN_USER_DEFAULTS_RULE_ID
                ):
                    continue
                extra = result.get("extra") or {}
                evidence = str(extra.get("lines") or extra.get("message") or result.get("check_id")).strip()
                path = str(result.get("path", "")).strip()
                return EvidenceEntry(True, f"{path}: {evidence}" if path else evidence)

            return EvidenceEntry(False, "no_sensitive_data_stored_in_user_defaults_hits")

        strings_outputs = loaded_outputs.get("strings_outputs") or {}
        if isinstance(strings_outputs, dict):
            for path, content in strings_outputs.items():
                text = str(content or "")
                lowered_text = text.lower()
                user_defaults_marker = next((marker for marker in cls.USER_DEFAULTS_MARKERS if marker in text), "")
                sensitive_marker = next((marker for marker in cls.SENSITIVE_DATA_MARKERS if marker in lowered_text), "")
                if user_defaults_marker and sensitive_marker:
                    return EvidenceEntry(True, f"(Triage Signal) {path}: {user_defaults_marker}; {sensitive_marker}")

        return EvidenceEntry(False, "no_sensitive_data_stored_in_user_defaults_hits")

    @classmethod
    def _logged_insecurely_entry(
        cls,
        loaded_outputs: dict[str, Any],
        *,
        rule_id: str,
        data_markers: tuple[str, ...],
        no_hit_evidence: str,
    ) -> EvidenceEntry:
        opengrep = loaded_outputs.get("opengrep")
        results = opengrep.get("results") if isinstance(opengrep, dict) else None
        if isinstance(results, list):
            for result in results:
                if not isinstance(result, dict) or result.get("check_id") != rule_id:
                    continue
                extra = result.get("extra") or {}
                evidence = str(extra.get("lines") or extra.get("message") or result.get("check_id")).strip()
                path = str(result.get("path", "")).strip()
                return EvidenceEntry(True, f"{path}: {evidence}" if path else evidence)

            return EvidenceEntry(False, no_hit_evidence)

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
                    return EvidenceEntry(True, f"(Triage Signal) {path}: {logging_marker}; {data_marker}")

        return EvidenceEntry(False, no_hit_evidence)

    @classmethod
    def _keyboard_cache_exposure_entry(cls, loaded_outputs: dict[str, Any]) -> EvidenceEntry:
        opengrep = loaded_outputs.get("opengrep")
        results = opengrep.get("results") if isinstance(opengrep, dict) else None
        if not isinstance(results, list):
            return EvidenceEntry(False, "keyboard_cache_exposure_not_assessed_binary_scan")

        for result in results:
            if not isinstance(result, dict) or result.get("check_id") != cls.KEYBOARD_CACHE_EXPOSURE_RULE_ID:
                continue
            extra = result.get("extra") or {}
            evidence = str(extra.get("lines") or extra.get("message") or result.get("check_id")).strip()
            path = str(result.get("path", "")).strip()
            return EvidenceEntry(True, f"{path}: {evidence}" if path else evidence)

        return EvidenceEntry(False, "no_keyboard_cache_exposure_hits")
