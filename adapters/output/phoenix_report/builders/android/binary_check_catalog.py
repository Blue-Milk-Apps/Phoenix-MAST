"""Canonical Android binary security checks and their evidence bindings."""

from __future__ import annotations

from dataclasses import dataclass

from domain.report import CheckSeverity


@dataclass(frozen=True)
class AndroidBinaryCheckDefinition:
    """A check that every Android binary report contains."""

    name: str
    severity: CheckSeverity


def _checks(
    severity: CheckSeverity,
    *names: str,
) -> tuple[AndroidBinaryCheckDefinition, ...]:
    return tuple(AndroidBinaryCheckDefinition(name=name, severity=severity) for name in names)


CODE_CHECKS = (
    *_checks(CheckSeverity.MEDIUM, "Accesses Unique Identifiers", "Contains Native Code", "Contains Reflection Code"),
    *_checks(
        CheckSeverity.HIGH,
        "Activities Accessible to Other Apps",
        "App is Debuggable",
        "Contains Hard-coded Cryptographic Key",
        "Contains Potential Hard-coded Password",
        "Contains Potential SQL Injection",
        "Creates Blowfish Key with Weak Length",
        "Creates RSA Keys with Weak Modulus Length",
    ),
    *_checks(CheckSeverity.MEDIUM, "Does not Update Security Provider"),
    *_checks(
        CheckSeverity.HIGH,
        "Receivers Accessible to Other Apps",
        "Requests Root Access",
        "Services Accessible to Other Apps",
    ),
    *_checks(
        CheckSeverity.MEDIUM,
        "SMS CVE-2014-8610",
        "Source Code is not Obfuscated",
    ),
    *_checks(CheckSeverity.HIGH, "Uses SHA1 Hashing Algorithm"),
    *_checks(
        CheckSeverity.MEDIUM,
        "Weakly Configured XML Parser",
        "Writes Sensitive Information to System Log",
    ),
    *_checks(CheckSeverity.HIGH, "Uses Spoofable Values for Authentication"),
    *_checks(CheckSeverity.MEDIUM, "Copies Sensitive Information into the Clipboard Without User Consent"),
)

NETWORK_CHECKS = (
    *_checks(
        CheckSeverity.HIGH,
        "Allows Cleartext Traffic for All Domains",
        "Contains HostnameVerifier That Accepts All Hostnames",
        "Contains X509TrustManager that Accepts All Certificates",
    ),
    *_checks(
        CheckSeverity.MEDIUM,
        "Does not Perform Certificate Pinning",
        "Opens a Listening Port",
        "Sensitive Cookies Lack Security Attributes",
    ),
    *_checks(CheckSeverity.LOW, "Unnecessary Information Transmitted"),
    *_checks(
        CheckSeverity.HIGH,
        "Sensitive Information is Unencrypted in Transit",
        "Password is not Hashed in Transit",
        "Weak Certificate Validation Enables MitM Attacks",
    ),
)

DATA_STORAGE_CHECKS = (
    *_checks(
        CheckSeverity.MEDIUM,
        "Accesses External Storage",
        "Does not Prevent Screen Capture of Sensitive Information",
    ),
    *_checks(
        CheckSeverity.HIGH,
        "Authentication Credentials Not Protected with Android Keystore",
        "Sensitive Information Stored in World Readable or Writable File in Internal Storage",
        "Sensitive Information Stored in External Storage",
    ),
)

RESILIENCE_CHECKS = _checks(
    CheckSeverity.MEDIUM,
    "Root Detection Missing",
    "Biometric / Local Authentication Bypass Possible",
)


def _normalized(name: str) -> str:
    return " ".join(name.lower().split())


EVIDENCE_KEY_BY_CHECK = {
    _normalized(name): key
    for name, key in (
        ("Accesses Unique Identifiers", "accesses_unique_identifiers"),
        ("Activities Accessible to Other Apps", "activities_accessible_to_other_apps"),
        ("App is Debuggable", "app_is_debuggable"),
        ("Contains Hard-coded Cryptographic Key", "contains_hard_coded_cryptographic_key"),
        ("Contains Native Code", "contains_native_code"),
        ("Contains Potential Hard-coded Password", "contains_potential_hard_coded_password"),
        ("Contains Potential SQL Injection", "contains_potential_sql_injection"),
        ("Contains Reflection Code", "contains_reflection_code"),
        ("Creates Blowfish Key with Weak Length", "creates_blowfish_key_with_weak_length"),
        ("Creates RSA Keys with Weak Modulus Length", "creates_rsa_keys_with_weak_modulus_length"),
        ("Does not Update Security Provider", "does_not_update_security_provider"),
        ("Receivers Accessible to Other Apps", "receivers_accessible_to_other_apps"),
        ("Requests Root Access", "requests_root_access"),
        ("Services Accessible to Other Apps", "services_accessible_to_other_apps"),
        ("SMS CVE-2014-8610", "sms_cve_2014_8610"),
        ("Source Code is not Obfuscated", "source_code_is_not_obfuscated"),
        ("Uses SHA1 Hashing Algorithm", "uses_sha1_hashing_algorithm"),
        ("Weakly Configured XML Parser", "weakly_configured_xml_parser"),
        ("Writes Sensitive Information to System Log", "writes_sensitive_information_to_system_log"),
        ("Uses Spoofable Values for Authentication", "uses_spoofable_values_for_authentication"),
        (
            "Copies Sensitive Information into the Clipboard Without User Consent",
            "copies_sensitive_information_into_clipboard_without_user_consent",
        ),
        ("Allows Cleartext Traffic for All Domains", "allows_cleartext_traffic_for_all_domains"),
        ("Contains HostnameVerifier That Accepts All Hostnames", "contains_hostname_verifier_accepts_all"),
        ("Contains X509TrustManager that Accepts All Certificates", "contains_x509_trust_manager_accepts_all"),
        ("Does not Perform Certificate Pinning", "does_not_perform_certificate_pinning"),
        ("Opens a Listening Port", "opens_listening_port"),
        ("Sensitive Cookies Lack Security Attributes", "sensitive_cookies_lack_security_attributes"),
        ("Unnecessary Information Transmitted", "unnecessary_information_transmitted"),
        ("Sensitive Information is Unencrypted in Transit", "sensitive_information_unencrypted_in_transit"),
        ("Password is not Hashed in Transit", "password_not_hashed_in_transit"),
        ("Weak Certificate Validation Enables MitM Attacks", "weak_certificate_validation_enables_mitm"),
        ("Accesses External Storage", "accesses_external_storage"),
        (
            "Authentication Credentials Not Protected with Android Keystore",
            "authentication_credentials_not_protected_with_android_keystore",
        ),
        (
            "Sensitive Information Stored in World Readable or Writable File in Internal Storage",
            "sensitive_information_stored_in_world_readable_or_writable_file_in_internal_storage",
        ),
        ("Sensitive Information Stored in External Storage", "sensitive_information_stored_in_external_storage"),
        (
            "Does not Prevent Screen Capture of Sensitive Information",
            "does_not_prevent_screen_capture_of_sensitive_information",
        ),
        ("Root Detection Missing", "root_detection_missing"),
        ("Biometric / Local Authentication Bypass Possible", "biometric_local_authentication_bypass_possible"),
    )
}

SECTION_CHECKS = (
    ("code", "Code Vulnerability", "code_evidence", CODE_CHECKS),
    ("network", "Networking", "network_evidence", NETWORK_CHECKS),
    ("data storage", "Data Storage", "data_storage_evidence", DATA_STORAGE_CHECKS),
    ("resilience", "Resilience", "resilience_evidence", RESILIENCE_CHECKS),
)
