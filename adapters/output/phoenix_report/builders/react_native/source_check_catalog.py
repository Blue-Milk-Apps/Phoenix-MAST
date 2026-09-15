"""Canonical React Native source checks and their evidence bindings."""

from adapters.output.phoenix_report.builders.android.source_check_catalog import ANDROID_SOURCE_SECTION_CHECKS
from adapters.output.phoenix_report.builders.ios.source_check_catalog import IOS_SOURCE_SECTION_CHECKS
from adapters.output.phoenix_report.builders.source import SourceCheckDefinition
from domain.report import CheckSeverity, ReportPlatform


def _definitions_by_key(
    sections: tuple[tuple[str, str, tuple[SourceCheckDefinition, ...]], ...],
) -> dict[str, SourceCheckDefinition]:
    return {definition.evidence_key: definition for _, _, definitions in sections for definition in definitions}


_ANDROID_DEFINITIONS = _definitions_by_key(ANDROID_SOURCE_SECTION_CHECKS)
_IOS_DEFINITIONS = _definitions_by_key(IOS_SOURCE_SECTION_CHECKS)

_REACT_NATIVE_DEFINITIONS = {
    "uses_dynamic_code_execution": SourceCheckDefinition(
        name="Uses Dynamic Code Execution",
        evidence_key="uses_dynamic_code_execution",
        severity=CheckSeverity.HIGH,
        applicable_platforms=frozenset({ReportPlatform.REACT_NATIVE}),
        compliance="MASVS-CODE-3",
        present_explanation="The app executes dynamically loaded or generated code.",
        not_present_explanation="No dynamic code execution was identified in the app.",
    ),
    "insecure_webview_configuration": SourceCheckDefinition(
        name="Insecure WebView Configuration",
        evidence_key="insecure_webview_configuration",
        severity=CheckSeverity.HIGH,
        applicable_platforms=frozenset({ReportPlatform.REACT_NATIVE}),
        compliance="MASVS-PLATFORM-2; MASVS-NETWORK-1",
        present_explanation="The app contains a WebView configuration that weakens origin or content security.",
        not_present_explanation="No insecure WebView configuration was identified in the app.",
    ),
    "copies_sensitive_information_into_clipboard_without_user_consent": SourceCheckDefinition(
        name="Copies Sensitive Information into the Clipboard Without User Consent",
        evidence_key="copies_sensitive_information_into_clipboard_without_user_consent",
        severity=CheckSeverity.HIGH,
        applicable_platforms=frozenset({ReportPlatform.REACT_NATIVE}),
        compliance="MASVS-STORAGE-2",
        present_explanation="The app copies sensitive information into the clipboard without the user's consent.",
        not_present_explanation="The app does not copy sensitive information into the clipboard without the user's consent.",
    ),
}


def _definition(evidence_key: str) -> SourceCheckDefinition:
    definition = (
        _REACT_NATIVE_DEFINITIONS.get(evidence_key)
        or _ANDROID_DEFINITIONS.get(evidence_key)
        or _IOS_DEFINITIONS.get(evidence_key)
    )
    if definition is None:
        raise KeyError(f"No React Native source check definition for {evidence_key}")
    return definition


def _section(
    name: str,
    evidence_key: str,
    evidence_keys: tuple[str, ...],
) -> tuple[str, str, tuple[SourceCheckDefinition, ...]]:
    return name, evidence_key, tuple(_definition(key) for key in evidence_keys)


REACT_NATIVE_SOURCE_SECTION_CHECKS = (
    _section(
        "Code",
        "code_evidence",
        (
            "activities_accessible_to_other_apps",
            "app_is_debuggable",
            "application_data_can_be_backed_up",
            "application_uses_custom_url_schemes_or_deep_links",
            "contains_hard_coded_cryptographic_key",
            "contains_potential_hard_coded_password",
            "contains_potential_sql_injection",
            "contains_reflection_code",
            "creates_blowfish_key_with_weak_length",
            "creates_rsa_keys_with_weak_modulus_length",
            "encodes_data_using_insecure_cryptography",
            "hardcoded_api_keys_in_bundle",
            "insecure_entitlements",
            "insecure_nanopb_library",
            "insecure_nskeyedunarchiver_usage",
            "pbkdf2_iteration_count_below_10k",
            "receivers_accessible_to_other_apps",
            "requests_root_access",
            "services_accessible_to_other_apps",
            "uses_dynamic_code_execution",
            "uses_sha1_hashing_algorithm",
            "uses_spoofable_values_for_authentication",
            "uses_uiwebview",
            "utilizes_insecure_cryptography",
            "weakly_configured_xml_parser",
            "writes_sensitive_information_to_system_log",
        ),
    ),
    _section(
        "Network",
        "network_evidence",
        (
            "allows_cleartext_traffic_for_all_domains",
            "ats_disabled",
            "ats_exceptions_configured",
            "certificate_pinning_not_implemented",
            "cleartext_http_advertiser_id",
            "cleartext_http_gps_latitude",
            "cleartext_http_gps_longitude",
            "cleartext_http_imei",
            "cleartext_http_sensitive_data",
            "cleartext_http_wifi_mac",
            "contains_hostname_verifier_accepts_all",
            "contains_x509_trust_manager_accepts_all",
            "cookie_missing_httponly",
            "cookie_missing_secure_flag",
            "https_url_contains_gps_latitude",
            "https_url_contains_gps_longitude",
            "https_url_contains_imei",
            "https_url_contains_sensitive_data",
            "https_url_contains_wifi_mac",
            "insecure_http_traffic",
            "insecure_tls_configuration",
            "insecure_webview_configuration",
            "opens_listening_port",
            "sensitive_information_unencrypted_in_transit",
            "uses_ftp",
            "vulnerable_openssl_ccs_injection",
            "vulnerable_openssl_heartbleed",
            "weak_certificate_validation_enables_mitm",
        ),
    ),
    _section(
        "Data Storage",
        "data_storage_evidence",
        (
            "accesses_external_storage",
            "advertiser_id_logged_insecurely",
            "advertiser_id_stored_insecurely",
            "copies_sensitive_information_into_clipboard_without_user_consent",
            "deprecated_keychain_attributes",
            "global_write_permissions",
            "hardcoded_api_keys_stored_insecurely",
            "hardcoded_passwords_stored_insecurely",
            "imei_labeled_value_stored_insecurely",
            "imei_logged_insecurely",
            "keyboard_cache_exposure",
            "keychain_items_accessible_after_first_unlock",
            "location_data_logged_insecurely",
            "location_data_stored_insecurely",
            "sensitive_data_logged_insecurely",
            "sensitive_data_stored_in_user_defaults",
            "sensitive_information_stored_in_external_storage",
            "sensitive_information_stored_in_world_readable_or_writable_file_in_internal_storage",
            "sensitive_values_stored_insecurely",
            "weak_file_protection",
            "wifi_ip_stored_insecurely",
            "wifi_mac_logged_insecurely",
        ),
    ),
    _section(
        "Resilience",
        "resilience_evidence",
        ("biometric_local_authentication_bypass_possible",),
    ),
)
