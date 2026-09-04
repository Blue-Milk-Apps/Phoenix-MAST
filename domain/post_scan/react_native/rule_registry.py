"""Explicit classification of Phoenix React Native OpenGrep rules."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum


class ReactNativeRuleDisposition(StrEnum):
    REPORT_VULNERABILITY = "report_vulnerability"
    FUNCTIONALITY = "functionality"
    INVENTORY = "inventory"
    RAW_ONLY = "raw_only"


@dataclass(frozen=True)
class ReactNativeRuleMapping:
    disposition: ReactNativeRuleDisposition
    section: str
    severity: str
    evidence_key: str = ""
    reason: str = ""
    applies_to: frozenset[str] = frozenset({"SOURCE"})


REPORT_RULE_IDS_BY_SECTION: dict[str, dict[str, frozenset[str]]] = {
    "Code": {
        "contains_potential_sql_injection": frozenset({"react-native.source.sql-injection"}),
        "encodes_data_using_insecure_cryptography": frozenset({"react-native.source.weak-hash"}),
        "creates_blowfish_key_with_weak_length": frozenset({"react-native.source.weak-blowfish-key"}),
        "creates_rsa_keys_with_weak_modulus_length": frozenset({"react-native.source.weak-rsa-key"}),
        "pbkdf2_iteration_count_below_10k": frozenset({"react-native.source.weak-pbkdf2-iterations"}),
        "utilizes_insecure_cryptography": frozenset({"react-native.source.weak-cipher"}),
        "uses_dynamic_code_execution": frozenset({"react-native.source.dynamic-code-execution"}),
        "uses_sha1_hashing_algorithm": frozenset({"react-native.source.sha1-hash"}),
        "uses_spoofable_values_for_authentication": frozenset({"react-native.source.spoofable-auth-identifier"}),
        "writes_sensitive_information_to_system_log": frozenset({"react-native.source.sensitive-log"}),
    },
    "Network": {
        "insecure_webview_configuration": frozenset(
            {
                "react-native.source.webview-mixed-content",
                "react-native.source.webview-wildcard-origin",
            }
        ),
        "cleartext_http_advertiser_id": frozenset({"react-native.source.cleartext-http-advertiser-id"}),
        "cleartext_http_gps_latitude": frozenset({"react-native.source.cleartext-http-gps-latitude"}),
        "cleartext_http_gps_longitude": frozenset({"react-native.source.cleartext-http-gps-longitude"}),
        "cleartext_http_imei": frozenset({"react-native.source.cleartext-http-imei"}),
        "cleartext_http_sensitive_data": frozenset({"react-native.source.cleartext-http-sensitive-data"}),
        "cleartext_http_wifi_mac": frozenset({"react-native.source.cleartext-http-wifi-mac"}),
        "cookie_missing_httponly": frozenset({"react-native.source.cookie-missing-httponly"}),
        "cookie_missing_secure_flag": frozenset({"react-native.source.cookie-missing-secure"}),
        "https_url_contains_gps_latitude": frozenset({"react-native.source.https-url-gps-latitude"}),
        "https_url_contains_gps_longitude": frozenset({"react-native.source.https-url-gps-longitude"}),
        "https_url_contains_imei": frozenset({"react-native.source.https-url-imei"}),
        "https_url_contains_sensitive_data": frozenset({"react-native.source.https-url-sensitive-data"}),
        "https_url_contains_wifi_mac": frozenset({"react-native.source.https-url-wifi-mac"}),
        "insecure_http_traffic": frozenset({"react-native.source.insecure-http-traffic"}),
        "insecure_tls_configuration": frozenset({"react-native.source.weak-tls-version"}),
        "sensitive_information_unencrypted_in_transit": frozenset({"react-native.source.cleartext-http"}),
        "uses_ftp": frozenset({"react-native.source.ftp-url"}),
        "weak_certificate_validation_enables_mitm": frozenset({"react-native.source.reject-unauthorized-disabled"}),
    },
    "Data Storage": {
        "copies_sensitive_information_into_clipboard_without_user_consent": frozenset(
            {"react-native.source.sensitive-clipboard"}
        ),
        "advertiser_id_logged_insecurely": frozenset({"react-native.source.advertiser-id-log"}),
        "advertiser_id_stored_insecurely": frozenset({"react-native.source.advertiser-id-storage"}),
        "deprecated_keychain_attributes": frozenset({"react-native.source.deprecated-keychain-accessibility"}),
        "global_write_permissions": frozenset({"react-native.source.global-write-permission"}),
        "hardcoded_api_keys_stored_insecurely": frozenset({"react-native.source.hardcoded-api-key-storage"}),
        "hardcoded_passwords_stored_insecurely": frozenset({"react-native.source.hardcoded-password-storage"}),
        "imei_labeled_value_stored_insecurely": frozenset({"react-native.source.imei-storage"}),
        "imei_logged_insecurely": frozenset({"react-native.source.imei-log"}),
        "keyboard_cache_exposure": frozenset({"react-native.source.keyboard-cache-exposure"}),
        "keychain_items_accessible_after_first_unlock": frozenset({"react-native.source.keychain-after-first-unlock"}),
        "location_data_logged_insecurely": frozenset({"react-native.source.location-log"}),
        "location_data_stored_insecurely": frozenset({"react-native.source.location-storage"}),
        "sensitive_data_stored_in_user_defaults": frozenset({"react-native.source.sensitive-user-defaults"}),
        "sensitive_values_stored_insecurely": frozenset(
            {
                "react-native.source.sensitive-async-storage",
                "react-native.source.sensitive-file-write",
            }
        ),
        "wifi_ip_stored_insecurely": frozenset({"react-native.source.wifi-ip-storage"}),
        "wifi_mac_logged_insecurely": frozenset({"react-native.source.wifi-mac-log"}),
    },
    "Resilience": {},
}

FUNCTIONALITY_RULE_ID_TO_KEY: dict[str, str] = {
    "react-native.functionality.audio": "Audio",
    "react-native.functionality.background-execution": "Background Execution",
    "react-native.functionality.biometric-authentication": "Biometric Authentication",
    "react-native.functionality.bluetooth": "Bluetooth",
    "react-native.functionality.calendar": "Calendar",
    "react-native.functionality.camera": "Camera",
    "react-native.functionality.camera-delegation": "Camera Delegation",
    "react-native.functionality.contacts": "Contacts",
    "react-native.functionality.device-administrator": "Device Administrator",
    "react-native.functionality.fingerprint": "Fingerprint",
    "react-native.functionality.geofencing": "Geofencing",
    "react-native.functionality.google-cloud-messaging": "Google Cloud Messaging",
    "react-native.functionality.health-data": "Health Data",
    "react-native.functionality.in-app-purchases": "In-App Purchases",
    "react-native.functionality.infrared-led": "Infrared LED",
    "react-native.functionality.keychain": "Keychain",
    "react-native.functionality.keystore": "Keystore",
    "react-native.functionality.location": "Location",
    "react-native.functionality.maps": "Maps",
    "react-native.functionality.microphone": "Microphone",
    "react-native.functionality.nearby-interaction": "Nearby Interaction",
    "react-native.functionality.networking": "Networking",
    "react-native.functionality.nfc": "NFC",
    "react-native.functionality.payment-services": "Payment Services",
    "react-native.functionality.photos": "Photos",
    "react-native.functionality.push-notifications": "Push Notifications",
    "react-native.functionality.secure-rng": "Secure RNG",
    "react-native.functionality.sensors": "Sensors",
    "react-native.functionality.sms": "SMS",
    "react-native.functionality.telephony": "Telephony",
    "react-native.functionality.usb-devices": "USB Devices",
}

ENDPOINT_INVENTORY_RULE_ID_TO_KEY: dict[str, str] = {
    "react-native.inventory.url-literal": "url_literal",
    "react-native.inventory.environment-endpoint": "environment_reference",
    "react-native.inventory.dynamic-base-url": "base_url_reference",
}
PERMISSION_INVENTORY_RULE_ID_TO_KEY: dict[str, str] = {
    "react-native.inventory.android-permission-request": "android_runtime_request",
    "react-native.inventory.cross-platform-permission-request": "cross_platform_runtime_request",
    "react-native.inventory.expo-permission-request": "expo_runtime_request",
}
INVENTORY_RULE_ID_TO_KEY: dict[str, str] = {
    **ENDPOINT_INVENTORY_RULE_ID_TO_KEY,
    **PERMISSION_INVENTORY_RULE_ID_TO_KEY,
}

RULE_SEVERITIES: dict[str, str] = {
    **{rule_id: "Info" for rule_id in INVENTORY_RULE_ID_TO_KEY},
    "react-native.source.advertiser-id-log": "Medium",
    "react-native.source.advertiser-id-storage": "High",
    "react-native.source.cleartext-http-advertiser-id": "High",
    "react-native.source.cleartext-http-gps-latitude": "High",
    "react-native.source.cleartext-http-gps-longitude": "High",
    "react-native.source.cleartext-http-imei": "High",
    "react-native.source.cleartext-http-sensitive-data": "High",
    "react-native.source.cleartext-http-wifi-mac": "High",
    "react-native.source.cleartext-http": "High",
    "react-native.source.cookie-missing-httponly": "Medium",
    "react-native.source.cookie-missing-secure": "Medium",
    "react-native.source.deprecated-keychain-accessibility": "Medium",
    "react-native.source.dynamic-code-execution": "High",
    "react-native.source.ftp-url": "High",
    "react-native.source.global-write-permission": "High",
    "react-native.source.hardcoded-api-key-storage": "High",
    "react-native.source.hardcoded-password-storage": "High",
    "react-native.source.https-url-gps-latitude": "Medium",
    "react-native.source.https-url-gps-longitude": "Medium",
    "react-native.source.https-url-imei": "Medium",
    "react-native.source.https-url-sensitive-data": "Medium",
    "react-native.source.https-url-wifi-mac": "Medium",
    "react-native.source.imei-log": "Medium",
    "react-native.source.imei-storage": "High",
    "react-native.source.insecure-http-traffic": "High",
    "react-native.source.insecure-randomness": "Medium",
    "react-native.source.keyboard-cache-exposure": "Medium",
    "react-native.source.keychain-after-first-unlock": "Medium",
    "react-native.source.location-log": "Medium",
    "react-native.source.location-storage": "High",
    "react-native.source.reject-unauthorized-disabled": "High",
    "react-native.source.sha1-hash": "High",
    "react-native.source.sensitive-async-storage": "High",
    "react-native.source.sensitive-clipboard": "High",
    "react-native.source.sensitive-file-write": "High",
    "react-native.source.sensitive-log": "Medium",
    "react-native.source.sensitive-native-module-call": "Medium",
    "react-native.source.sql-injection": "High",
    "react-native.source.spoofable-auth-identifier": "High",
    "react-native.source.sensitive-user-defaults": "High",
    "react-native.source.weak-cipher": "High",
    "react-native.source.weak-blowfish-key": "High",
    "react-native.source.weak-hash": "High",
    "react-native.source.weak-pbkdf2-iterations": "High",
    "react-native.source.weak-rsa-key": "High",
    "react-native.source.weak-tls-version": "High",
    "react-native.source.webview-message-bridge": "Medium",
    "react-native.source.webview-mixed-content": "High",
    "react-native.source.webview-wildcard-origin": "High",
    "react-native.source.wifi-ip-storage": "High",
    "react-native.source.wifi-mac-log": "Medium",
    **{rule_id: "Info" for rule_id in FUNCTIONALITY_RULE_ID_TO_KEY},
}

RAW_ONLY_RULE_REASONS: dict[str, str] = {
    "react-native.source.insecure-randomness": (
        "Math.random requires manual review because the surrounding value may not be security-sensitive."
    ),
    "react-native.source.sensitive-native-module-call": (
        "Native module calls cross a trust boundary, but their native implementation determines whether they are unsafe."
    ),
    "react-native.source.webview-message-bridge": (
        "WebView message bridges require origin, validation, and handler review before they can be classified as unsafe."
    ),
}


def _report_mappings() -> dict[str, ReactNativeRuleMapping]:
    mappings: dict[str, ReactNativeRuleMapping] = {}
    for section, evidence_groups in REPORT_RULE_IDS_BY_SECTION.items():
        for evidence_key, rule_ids in evidence_groups.items():
            for rule_id in rule_ids:
                mappings[rule_id] = ReactNativeRuleMapping(
                    disposition=ReactNativeRuleDisposition.REPORT_VULNERABILITY,
                    section=section,
                    severity=RULE_SEVERITIES[rule_id],
                    evidence_key=evidence_key,
                )
    return mappings


def _build_registry() -> dict[str, ReactNativeRuleMapping]:
    registry = _report_mappings()
    registry.update(
        {
            rule_id: ReactNativeRuleMapping(
                disposition=ReactNativeRuleDisposition.INVENTORY,
                section="Endpoints",
                severity=RULE_SEVERITIES[rule_id],
                evidence_key=evidence_key,
            )
            for rule_id, evidence_key in ENDPOINT_INVENTORY_RULE_ID_TO_KEY.items()
        }
    )
    registry.update(
        {
            rule_id: ReactNativeRuleMapping(
                disposition=ReactNativeRuleDisposition.INVENTORY,
                section="Permissions",
                severity=RULE_SEVERITIES[rule_id],
                evidence_key=evidence_key,
            )
            for rule_id, evidence_key in PERMISSION_INVENTORY_RULE_ID_TO_KEY.items()
        }
    )
    registry.update(
        {
            rule_id: ReactNativeRuleMapping(
                disposition=ReactNativeRuleDisposition.FUNCTIONALITY,
                section="Functionality",
                severity=RULE_SEVERITIES[rule_id],
                evidence_key=capability,
            )
            for rule_id, capability in FUNCTIONALITY_RULE_ID_TO_KEY.items()
        }
    )
    registry.update(
        {
            rule_id: ReactNativeRuleMapping(
                disposition=ReactNativeRuleDisposition.RAW_ONLY,
                section="Raw",
                severity=RULE_SEVERITIES[rule_id],
                reason=reason,
            )
            for rule_id, reason in RAW_ONLY_RULE_REASONS.items()
        }
    )
    return registry


REACT_NATIVE_RULE_REGISTRY = _build_registry()
REACT_NATIVE_RULE_IDS = frozenset(REACT_NATIVE_RULE_REGISTRY)


def unclassified_react_native_rule_ids(rule_ids: set[str] | frozenset[str]) -> set[str]:
    """Return React Native rule IDs without an explicit report disposition."""

    return set(rule_ids) - set(REACT_NATIVE_RULE_IDS)
