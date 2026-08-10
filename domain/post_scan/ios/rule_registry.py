"""Explicit classification and consumers for the default iOS OpenGrep rules."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum


class IOSRuleDisposition(StrEnum):
    REPORT_VULNERABILITY = "report_vulnerability"
    FUNCTIONALITY = "functionality"
    POSITIVE_INFORMATIONAL = "positive_informational"
    RAW_ONLY = "raw_only"


@dataclass(frozen=True)
class IOSRuleMapping:
    disposition: IOSRuleDisposition
    section: str
    evidence_key: str = ""
    reason: str = ""
    applies_to: frozenset[str] = frozenset({"BINARY", "SOURCE"})


CODE_RULE_IDS_BY_EVIDENCE_KEY: dict[str, frozenset[str]] = {
    "uses_uiwebview": frozenset({"ios-deprecated-api-uiwebview"}),
    "insecure_nskeyedunarchiver_usage": frozenset({"ios-insecure-serialization-nskeyedunarchiver"}),
    "encodes_data_using_insecure_cryptography": frozenset(
        {
            "ios-weak-crypto-md5",
            "ios-weak-crypto-operation-3des",
            "ios-weak-crypto-operation-des",
            "ios-weak-crypto-operation-ecb",
            "ios-weak-crypto-operation-rc4",
            "ios-weak-crypto-sha1",
        }
    ),
    "utilizes_insecure_cryptography": frozenset(
        {
            "ios-weak-crypto-reference-3des",
            "ios-weak-crypto-reference-des",
            "ios-weak-crypto-reference-rc4",
        }
    ),
    "pbkdf2_iteration_count_below_10k": frozenset({"ios-pbkdf2-low-iterations"}),
}

NETWORK_RULE_IDS_BY_EVIDENCE_KEY: dict[str, frozenset[str]] = {
    "ats_disabled": frozenset({"ats-disabled-usage"}),
    "ats_exceptions_configured": frozenset({"ats-exceptions-usage"}),
    "cookie_missing_httponly": frozenset({"ios.network.cookie-missing-httponly"}),
    "cookie_missing_secure_flag": frozenset({"ios.network.cookie-missing-secure-flag"}),
}

_FILE_PROTECTION_SCOPES = ("applevel", "filelevel", "filemgr", "existingfile", "coredata")
WEAK_FILE_PROTECTION_RULE_IDS = frozenset(
    f"fileprotection-{protection}-{scope}"
    for protection in ("open", "firstunlock", "none")
    for scope in _FILE_PROTECTION_SCOPES
)
COMPLETE_FILE_PROTECTION_RULE_IDS = frozenset(f"fileprotection-complete-{scope}" for scope in _FILE_PROTECTION_SCOPES)

DATA_STORAGE_RULE_IDS_BY_EVIDENCE_KEY: dict[str, frozenset[str]] = {
    "weak_file_protection": WEAK_FILE_PROTECTION_RULE_IDS,
    "deprecated_keychain_attributes": frozenset({"ios.storage.deprecated-keychain-accessibility"}),
    "advertiser_id_stored_insecurely": frozenset({"ios.storage.advertiser-id-insecure-storage"}),
    "imei_labeled_value_stored_insecurely": frozenset({"ios.storage.imei-labeled-value-insecure-storage"}),
    "global_write_permissions": frozenset({"ios.storage.global-write-permissions"}),
    "location_data_stored_insecurely": frozenset({"ios.storage.location-data-insecure-storage"}),
    "hardcoded_api_keys_stored_insecurely": frozenset({"ios.storage.hardcoded-api-key-insecure-storage"}),
    "hardcoded_passwords_stored_insecurely": frozenset({"ios.storage.hardcoded-password-insecure-storage"}),
    "sensitive_values_stored_insecurely": frozenset({"ios.storage.sensitive-value-insecure-storage"}),
    "wifi_ip_stored_insecurely": frozenset({"ios.storage.wifi-ip-insecure-storage"}),
    "keychain_items_accessible_after_first_unlock": frozenset(
        {"ios.storage.keychain-items-accessible-after-first-unlock"}
    ),
    "sensitive_data_stored_in_user_defaults": frozenset({"ios.storage.sensitive-data-in-user-defaults"}),
    "advertiser_id_logged_insecurely": frozenset({"ios.storage.advertiser-id-logged-insecurely"}),
    "imei_logged_insecurely": frozenset({"ios.storage.imei-logged-insecurely"}),
    "location_data_logged_insecurely": frozenset({"ios.storage.location-data-logged-insecurely"}),
    "sensitive_data_logged_insecurely": frozenset({"ios.storage.sensitive-data-logged-insecurely"}),
    "wifi_mac_logged_insecurely": frozenset({"ios.storage.wifi-mac-logged-insecurely"}),
    "keyboard_cache_exposure": frozenset({"ios.storage.keyboard-cache-exposure"}),
}
DATA_STORAGE_RULE_ID_BY_EVIDENCE_KEY = {
    evidence_key: next(iter(rule_ids))
    for evidence_key, rule_ids in DATA_STORAGE_RULE_IDS_BY_EVIDENCE_KEY.items()
    if len(rule_ids) == 1
}

REPORT_RULE_IDS_BY_SECTION: dict[str, dict[str, frozenset[str]]] = {
    "Code": CODE_RULE_IDS_BY_EVIDENCE_KEY,
    "Network": NETWORK_RULE_IDS_BY_EVIDENCE_KEY,
    "Data Storage": DATA_STORAGE_RULE_IDS_BY_EVIDENCE_KEY,
    "Resilience": {},
}

FUNCTIONALITY_RULE_ID_TO_KEY: dict[str, str] = {
    "ios.location.usage-description.present": "Location",
    "network-local-desc": "Networking",
    "cam-lowlevel-usage": "Camera",
    "cam-platform-usage": "Camera",
    "cam-usage-desc": "Camera",
    "mic-usage-desc": "Microphone",
    "loc-usage-desc": "Location",
    "nfc-usage-desc": "NFC",
    "nfc-reader-usage": "NFC",
    "iokit-usage-desc": "USB Devices",
    "bt-usage-desc": "Bluetooth",
    "nearby-usage-desc": "Nearby Interaction",
    "keychain-write-native": "Keychain",
    "lowlevel-networking-usage": "Networking",
    "lowlevel-CFNetworking-usage": "Networking",
    "push-notification-usage": "Push Notifications",
    "push-notification-background-usage": "Push Notifications",
    "contacts-usage-desc": "Contacts",
    "calendar-usage-desc": "Calendar",
    "audio-parser-usage": "Audio",
    "crypto-platform-drbg": "Secure RNG",
    "crypto-api-drbg": "Secure RNG",
    "ats-exceptions-usage": "Networking",
    "ats-disabled-usage": "Networking",
}

_LOCATION_PERMISSION_KEYS = (
    "NSLocationWhenInUseUsageDescription",
    "NSLocationAlwaysAndWhenInUseUsageDescription",
    "NSLocationAlwaysUsageDescription",
)
PERMISSION_RULE_ID_TO_KEYS: dict[str, tuple[str, ...]] = {
    "ios.location.usage-description.present": _LOCATION_PERMISSION_KEYS,
    "network-local-desc": ("NSLocalNetworkUsageDescription",),
    "cam-usage-desc": ("NSCameraUsageDescription",),
    "mic-usage-desc": ("NSMicrophoneUsageDescription",),
    "loc-usage-desc": _LOCATION_PERMISSION_KEYS,
    "nfc-usage-desc": ("NFCReaderUsageDescription",),
    "bt-usage-desc": ("NSBluetoothAlwaysUsageDescription", "NSBluetoothPeripheralUsageDescription"),
    "nearby-usage-desc": ("NSNearbyInteractionUsageDescription",),
    "contacts-usage-desc": ("NSContactsUsageDescription",),
    "calendar-usage-desc": ("NSCalendarsUsageDescription",),
}

POSITIVE_INFORMATIONAL_RULE_SECTION_BY_ID: dict[str, str] = {
    "crypto-platform-drbg": "Code",
    "crypto-api-drbg": "Code",
    "crypto-platform-keygen": "Code",
    **{rule_id: "Data Storage" for rule_id in COMPLETE_FILE_PROTECTION_RULE_IDS},
}
POSITIVE_INFORMATIONAL_RULE_IDS = frozenset(POSITIVE_INFORMATIONAL_RULE_SECTION_BY_ID)
POSITIVE_RULE_IDS_BY_EVIDENCE_KEY: dict[str, frozenset[str]] = {
    "weak_file_protection": COMPLETE_FILE_PROTECTION_RULE_IDS,
}

RAW_ONLY_RULE_REASONS: dict[str, str] = {
    "antix-mmap-usage": "Low-level API usage is retained for manual review; no dedicated report check exists.",
    "antix-mprotect-usage": "Low-level API usage is retained for manual review; no dedicated report check exists.",
    "json-parser-usage": "Parser inventory is informational and has no matching report or capability field.",
    "xml-parser-usage": "Parser inventory is informational and has no matching report or capability field.",
    "plist-parser-usage": "Parser inventory is informational and has no matching report or capability field.",
    "video-parser-usage": "Parser inventory is informational and has no matching report or capability field.",
    "private-api-usage-convention": "Potential private API usage needs a dedicated source report check before promotion.",
    "private-api-usage-dynamic": "Potential private API usage needs a dedicated source report check before promotion.",
    "private-api-usage-unsafebitcast": "Potential private API usage needs a dedicated source report check before promotion.",
    "config-storage-usage": "UserDefaults usage alone does not establish insecure storage.",
    "settings-bundle-usage": "Settings bundle usage is informational and has no matching capability field.",
}

SOURCE_ONLY_RULE_IDS = frozenset(
    {
        "ios.storage.keyboard-cache-exposure",
        "ios.storage.global-write-permissions",
        "ios.storage.imei-labeled-value-insecure-storage",
        "ios.storage.advertiser-id-insecure-storage",
        "ios.network.cookie-missing-httponly",
        "ios.network.cookie-missing-secure-flag",
    }
)


def _report_mappings() -> dict[str, IOSRuleMapping]:
    mappings: dict[str, IOSRuleMapping] = {}
    for section, evidence_groups in REPORT_RULE_IDS_BY_SECTION.items():
        for evidence_key, rule_ids in evidence_groups.items():
            for rule_id in rule_ids:
                mappings[rule_id] = IOSRuleMapping(
                    disposition=IOSRuleDisposition.REPORT_VULNERABILITY,
                    section=section,
                    evidence_key=evidence_key,
                    applies_to=frozenset({"SOURCE"})
                    if rule_id in SOURCE_ONLY_RULE_IDS
                    else frozenset({"BINARY", "SOURCE"}),
                )
    return mappings


def _build_registry() -> dict[str, IOSRuleMapping]:
    registry = _report_mappings()
    functionality_rule_ids = set(FUNCTIONALITY_RULE_ID_TO_KEY) - set(registry) - set(POSITIVE_INFORMATIONAL_RULE_IDS)
    registry.update(
        {
            rule_id: IOSRuleMapping(IOSRuleDisposition.FUNCTIONALITY, "Functionality")
            for rule_id in functionality_rule_ids
        }
    )
    registry.update(
        {
            rule_id: IOSRuleMapping(IOSRuleDisposition.POSITIVE_INFORMATIONAL, section)
            for rule_id, section in POSITIVE_INFORMATIONAL_RULE_SECTION_BY_ID.items()
        }
    )
    registry.update(
        {
            rule_id: IOSRuleMapping(IOSRuleDisposition.RAW_ONLY, "Raw", reason=reason)
            for rule_id, reason in RAW_ONLY_RULE_REASONS.items()
        }
    )
    return registry


IOS_RULE_REGISTRY = _build_registry()
IOS_RULE_IDS = frozenset(IOS_RULE_REGISTRY)


def unclassified_ios_rule_ids(rule_ids: set[str] | frozenset[str]) -> set[str]:
    """Return default-bundle rule IDs that have no explicit classification."""

    return set(rule_ids) - set(IOS_RULE_IDS)
