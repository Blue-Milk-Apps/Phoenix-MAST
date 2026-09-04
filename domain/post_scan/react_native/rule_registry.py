"""Explicit classification of Phoenix React Native OpenGrep rules."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum


class ReactNativeRuleDisposition(StrEnum):
    REPORT_VULNERABILITY = "report_vulnerability"
    FUNCTIONALITY = "functionality"
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
        "utilizes_insecure_cryptography": frozenset({"react-native.source.weak-cipher"}),
        "uses_dynamic_code_execution": frozenset({"react-native.source.dynamic-code-execution"}),
        "writes_sensitive_information_to_system_log": frozenset({"react-native.source.sensitive-log"}),
    },
    "Network": {
        "insecure_webview_configuration": frozenset(
            {
                "react-native.source.webview-mixed-content",
                "react-native.source.webview-wildcard-origin",
            }
        ),
        "sensitive_information_unencrypted_in_transit": frozenset({"react-native.source.cleartext-http"}),
        "weak_certificate_validation_enables_mitm": frozenset({"react-native.source.reject-unauthorized-disabled"}),
    },
    "Data Storage": {
        "copies_sensitive_information_into_clipboard_without_user_consent": frozenset(
            {"react-native.source.sensitive-clipboard"}
        ),
        "sensitive_values_stored_insecurely": frozenset(
            {
                "react-native.source.sensitive-async-storage",
                "react-native.source.sensitive-file-write",
            }
        ),
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

RULE_SEVERITIES: dict[str, str] = {
    "react-native.source.cleartext-http": "High",
    "react-native.source.dynamic-code-execution": "High",
    "react-native.source.insecure-randomness": "Medium",
    "react-native.source.reject-unauthorized-disabled": "High",
    "react-native.source.sensitive-async-storage": "High",
    "react-native.source.sensitive-clipboard": "High",
    "react-native.source.sensitive-file-write": "High",
    "react-native.source.sensitive-log": "Medium",
    "react-native.source.sensitive-native-module-call": "Medium",
    "react-native.source.sql-injection": "High",
    "react-native.source.weak-cipher": "High",
    "react-native.source.weak-hash": "High",
    "react-native.source.webview-message-bridge": "Medium",
    "react-native.source.webview-mixed-content": "High",
    "react-native.source.webview-wildcard-origin": "High",
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
