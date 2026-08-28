"""Explicit classification of Phoenix Android OpenGrep rules."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum


class AndroidRuleDisposition(StrEnum):
    REPORT_VULNERABILITY = "report_vulnerability"
    FUNCTIONALITY = "functionality"
    POSITIVE_INFORMATIONAL = "positive_informational"
    RAW_ONLY = "raw_only"


@dataclass(frozen=True)
class AndroidRuleMapping:
    disposition: AndroidRuleDisposition
    section: str
    evidence_key: str = ""
    applies_to: frozenset[str] = frozenset({"SOURCE"})


FUNCTIONALITY_RULE_IDS = frozenset(
    {
        "android.location.services.present",
        "android.maps.usage.present",
        "android.networking.usage.present",
        "android.background.execution.present",
        "android.push.messaging.present",
        "android.camera.usage.present",
        "android.microphone.usage.present",
        "android.nfc.usage.present",
        "android.fingerprint.usage.present",
        "android.bluetooth.usage.present",
        "android.sms.usage.present",
        "android.telephony.usage.present",
        "android.contacts.usage.present",
        "android.photos.usage.present",
        "android.in_app_purchases.usage.present",
        "android.device.administrator.usage.present",
        "android.camera.delegation.usage.present",
        "android.sensors.usage.present",
        "android.calendar.usage.present",
        "android.usb.devices.usage.present",
        "android.geofencing.usage.present",
        "android.health.data.usage.present",
        "android.infrared.led.usage.present",
        "android.audio.usage.present",
        "android.payment.services.usage.present",
        "android.secure.rng.usage.present",
        "android.keystore.usage.present",
    }
)

REPORT_RULE_IDS_BY_SECTION: dict[str, dict[str, frozenset[str]]] = {
    "Code": {
        "contains_potential_sql_injection": frozenset({"android.source.sql-injection"}),
        "contains_reflection_code": frozenset({"android.source.reflection"}),
        "creates_blowfish_key_with_weak_length": frozenset({"android.source.weak-blowfish-key"}),
        "creates_rsa_keys_with_weak_modulus_length": frozenset({"android.source.weak-rsa-key"}),
        "requests_root_access": frozenset({"android.source.root-exec"}),
        "uses_sha1_hashing_algorithm": frozenset({"android.source.sha1"}),
        "weakly_configured_xml_parser": frozenset({"android.source.weak-xml-parser"}),
        "writes_sensitive_information_to_system_log": frozenset({"android.source.sensitive-log"}),
        "uses_spoofable_values_for_authentication": frozenset({"android.source.spoofable-auth"}),
        "copies_sensitive_information_into_clipboard_without_user_consent": frozenset(
            {"android.source.sensitive-clipboard"}
        ),
    },
    "Network": {
        "contains_hostname_verifier_accepts_all": frozenset({"android.source.accept-all-hostname-verifier"}),
        "contains_x509_trust_manager_accepts_all": frozenset({"android.source.accept-all-trust-manager"}),
        "opens_listening_port": frozenset({"android.source.listening-socket"}),
        "sensitive_information_unencrypted_in_transit": frozenset({"android.source.cleartext-http"}),
    },
    "Data Storage": {
        "sensitive_information_stored_in_world_readable_or_writable_file_in_internal_storage": frozenset(
            {"android.source.world-readable-file"}
        ),
        "sensitive_information_stored_in_external_storage": frozenset({"android.source.sensitive-external-storage"}),
    },
    "Resilience": {
        "biometric_local_authentication_bypass_possible": frozenset({"android.source.unsafe-biometric-auth"}),
    },
}


def _build_registry() -> dict[str, AndroidRuleMapping]:
    registry = {
        rule_id: AndroidRuleMapping(AndroidRuleDisposition.FUNCTIONALITY, "Functionality")
        for rule_id in FUNCTIONALITY_RULE_IDS
    }
    for section, groups in REPORT_RULE_IDS_BY_SECTION.items():
        for evidence_key, rule_ids in groups.items():
            for rule_id in rule_ids:
                registry[rule_id] = AndroidRuleMapping(
                    AndroidRuleDisposition.REPORT_VULNERABILITY,
                    section,
                    evidence_key,
                )
    return registry


ANDROID_RULE_REGISTRY = _build_registry()
ANDROID_RULE_IDS = frozenset(ANDROID_RULE_REGISTRY)


def unclassified_android_rule_ids(rule_ids: set[str] | frozenset[str]) -> set[str]:
    """Return bundled Android rule IDs without an explicit disposition."""

    return set(rule_ids) - set(ANDROID_RULE_IDS)
