#!/usr/bin/env python3
"""
Phoenix Security Report generator.

Usage:
    python3 generate_report.py <data.json> <output.pdf>

Feed it a JSON file matching the schema in data/blank_template.json (a filled
example is at data/sample_insecurebankv2.json) and it renders a PDF report in
the phoenix / mobile-app-pentest style: cover page, risk donuts, overall
evaluation table, certificate/file/app info, functionality & SDK inventory,
permissions, one section per vulnerability category with a findings narrative
and a checks-conducted table, hardcoded values, and endpoint connections.
"""

import base64
import copy
import io
import json
import os
import sys
from pathlib import Path
from typing import Any

BASE_DIR = Path(__file__).parent
TEMPLATES_DIR = BASE_DIR / "templates"
BLANK_TEMPLATE_PATH = BASE_DIR / "data" / "blank_template.json"
IOS_BLANK_TEMPLATE_PATH = BASE_DIR / "data" / "ios_blank_template.json"

RISK_LEVEL_ORDER = {"low": 1, "medium": 2, "high": 3}
RISK_LEVEL_COLOR = {"low": "#2980b9", "medium": "#e08e0b", "high": "#c0392b"}
FINDINGS_SEVERITY_KEYS = ("critical", "high", "medium", "low", "info", "secure")
SECTION_TO_AREA = {
    "code": ("Code Vulnerability", "code_vulnerability"),
    "storage": ("Data Storage", "data_storage"),
    "network": ("Networking", "networking"),
    "resilience": ("Resilience", "resilience"),
}
# iOS uses "Data" (not "Data Storage") as both the section name and the risk
# summary/polar-chart key -- make_overall_risk_polar_chart() derives its axis
# label straight from the risk_summary key, so keying this as "data" (one
# word) is what makes the chart print "Data" instead of an auto title-cased
# "Data Storage".
IOS_SECTION_TO_AREA = {
    "code": ("Code Vulnerability", "code_vulnerability"),
    "data": ("Data", "data"),
    "network": ("Networking", "networking"),
    "resilience": ("Resilience", "resilience"),
}
SECTION_SEVERITY_ORDER = {
    "critical": 5,
    "high": 4,
    "medium": 3,
    "low": 2,
    "info": 1,
    "secure": 0,
}

# iOS evidence-key mappings -- the same shape/precedence as Android's
# CODE_EVIDENCE_KEY_BY_CHECK / NETWORK_EVIDENCE_KEY_BY_CHECK /
# STORAGE_EVIDENCE_KEY_BY_CHECK / RESILIENCE_EVIDENCE_KEY_BY_CHECK. A
# post-scan-processing pipeline (ipsw/LIEF/plist/opengrep) is expected to
# emit `code_evidence` / `network_evidence` / `data_evidence` /
# `resilience_evidence` dicts keyed by these snake_case names, each holding
# {"present": bool, "evidence": str}. iOS's 4th section is `data_evidence`
# (not `storage_evidence`) to match the "Data" section rename.
IOS_CODE_EVIDENCE_KEY_BY_CHECK = {
    "deprecated api - uiwebview": "uses_uiwebview",
    "insecure nanopb library": "insecure_nanopb_library",
    "insecure serialization api - nskeyedunarchiver": "insecure_nskeyedunarchiver_usage",
    "missing arc binary protections": "missing_arc",
    "position-independent code (pic) not enabled": "pic_not_enabled",
    "stack canaries not enabled": "stack_canaries_not_enabled",
    "insecure api usage in binary": "insecure_api_usage_in_binary",
    "usage of malloc instead of calloc in binary": "malloc_instead_of_calloc",
    "application encodes data using insecure cryptography": "encodes_data_using_insecure_cryptography",
    "application utilizes insecure cryptography": "utilizes_insecure_cryptography",
    "pbkdf2 iteration count <10k": "pbkdf2_iteration_count_below_10k",
    "hardcoded api keys within the application bundle": "hardcoded_api_keys_in_bundle",
    "potentially insecure ios entitlements": "insecure_entitlements",
}
IOS_NETWORK_EVIDENCE_KEY_BY_CHECK = {
    "app transport security (ats) disabled": "ats_disabled",
    "change cipher spec injection vulnerable openssl version": "vulnerable_openssl_ccs_injection",
    "application contains deprecated ftp functionality": "uses_ftp",
    "application contains heartbleed vulnerable openssl version": "vulnerable_openssl_heartbleed",
    "application contains insecure http traffic": "insecure_http_traffic",
    "application selectively disabled app transport security protections": "ats_exceptions_configured",
    "cookie missing 'httponly' flag": "cookie_missing_httponly",
    "cookie missing 'secure' flag": "cookie_missing_secure_flag",
    "http cleartext transmission of advertiser id": "cleartext_http_advertiser_id",
    "http cleartext transmission of device imei": "cleartext_http_imei",
    "http cleartext transmission of gps latitude coordinates": "cleartext_http_gps_latitude",
    "http cleartext transmission of gps longitude coordinates": "cleartext_http_gps_longitude",
    "http cleartext transmission of sensitive data": "cleartext_http_sensitive_data",
    "http cleartext transmission of wifi mac address": "cleartext_http_wifi_mac",
    "https traffic url contains device imei": "https_url_contains_imei",
    "https traffic url contains device's gps latitude": "https_url_contains_gps_latitude",
    "https traffic url contains device's gps longitude": "https_url_contains_gps_longitude",
    "https traffic url contains sensitive data": "https_url_contains_sensitive_data",
    "https traffic url contains wifi mac address": "https_url_contains_wifi_mac",
    "insecure tls configuration": "insecure_tls_configuration",
    "certificate pinning not implemented": "certificate_pinning_not_implemented",
}
IOS_DATA_EVIDENCE_KEY_BY_CHECK = {
    "application utilizes deprecated keychain attributes": "deprecated_keychain_attributes",
    "local data exposure: advertiser id stored insecurely": "advertiser_id_stored_insecurely",
    "local data exposure: imei-labeled value stored insecurely": "imei_labeled_value_stored_insecurely",
    "local data exposure: global write permissions (source code only)": "global_write_permissions",
    "local data exposure: location data stored insecurely": "location_data_stored_insecurely",
    "local data exposure: insecure hardcoded api keys": "hardcoded_api_keys_stored_insecurely",
    "local data exposure: insecure hardcoded passwords": "hardcoded_passwords_stored_insecurely",  # pragma: allowlist secret
    "local data exposure: sensitive values stored insecurely": "sensitive_values_stored_insecurely",
    "local data exposure: wifi ip address stored insecurely": "wifi_ip_stored_insecurely",
    "keychain items accessible after first unlock": "keychain_items_accessible_after_first_unlock",
    "sensitive data stored in user defaults": "sensitive_data_stored_in_user_defaults",
    "local data exposure: advertiser id logged insecurely": "advertiser_id_logged_insecurely",
    "local data exposure: device imei logged insecurely": "imei_logged_insecurely",
    "local data exposure: location data logged insecurely": "location_data_logged_insecurely",
    "local data exposure: sensitive data logged insecurely": "sensitive_data_logged_insecurely",
    "local data exposure: wifi mac address logged insecurely": "wifi_mac_logged_insecurely",
    "sensitive data exposed through device keyboard cache (source code only)": "keyboard_cache_exposure",
}
IOS_RESILIENCE_EVIDENCE_KEY_BY_CHECK = {
    "biometric / local authentication bypass possible": "biometric_bypass_possible",
    "components contain debug symbols": "debug_symbols_present",
}
IOS_SECTION_EVIDENCE = {
    "code": ("code_evidence", IOS_CODE_EVIDENCE_KEY_BY_CHECK),
    "network": ("network_evidence", IOS_NETWORK_EVIDENCE_KEY_BY_CHECK),
    "data": ("data_evidence", IOS_DATA_EVIDENCE_KEY_BY_CHECK),
    "resilience": ("resilience_evidence", IOS_RESILIENCE_EVIDENCE_KEY_BY_CHECK),
}

DERIVED_CHECK_ALIAS_TO_COMPONENT_KEY = {
    "unprotected exported activity": "exported_activities",
    "activities accessible to other apps": "exported_activities",
    "unprotected exported service": "exported_services",
    "services accessible to other apps": "exported_services",
    "unprotected exported receiver": "exported_receivers",
    "receivers accessible to other apps": "exported_receivers",
    "unprotected exported provider": "exported_providers",
    "providers accessible to other apps": "exported_providers",
}
SHARED_PREFS_HINTS = ("shared_prefs/", "/shared_prefs/", "shared_prefs\\")
CACHE_HINTS = ("cache/", "/cache/", "cache\\", "webviewcache", "httpcache")
DEPRECATED_NETWORK_CHECK_NAMES = {
    "api authentication weakness (weak token handling / api key used as authentication)",
}
NETWORK_EVIDENCE_KEY_BY_CHECK = {
    "allows cleartext traffic for all domains": "allows_cleartext_traffic_for_all_domains",
    "contains hostnameverifier that accepts all hostnames": "contains_hostname_verifier_accepts_all",
    "contains x509trustmanager that accepts all certificates": "contains_x509_trust_manager_accepts_all",
    "does not perform certificate pinning": "does_not_perform_certificate_pinning",
    "opens a listening port": "opens_listening_port",
    "sensitive cookies lack security attributes": "sensitive_cookies_lack_security_attributes",
    "unnecessary information transmitted": "unnecessary_information_transmitted",
    "sensitive information is unencrypted in transit": "sensitive_information_unencrypted_in_transit",
    "password is not hashed in transit": "password_not_hashed_in_transit",
    "weak certificate validation enables mitm attacks": "weak_certificate_validation_enables_mitm",
}
STORAGE_EVIDENCE_KEY_BY_CHECK = {
    "accesses external storage": "accesses_external_storage",
    "authentication credentials not protected with android keystore": (
        "authentication_credentials_not_protected_with_android_keystore"
    ),
    "sensitive information stored in world readable or writable file in internal storage": (
        "sensitive_information_stored_in_world_readable_or_writable_file_in_internal_storage"
    ),
    "sensitive information stored in external storage": ("sensitive_information_stored_in_external_storage"),
    "does not prevent screen capture of sensitive information": (
        "does_not_prevent_screen_capture_of_sensitive_information"
    ),
}
RESILIENCE_EVIDENCE_KEY_BY_CHECK = {
    "root detection missing": "root_detection_missing",
    "biometric / local authentication bypass possible": "biometric_local_authentication_bypass_possible",
}
CODE_EVIDENCE_KEY_BY_CHECK = {
    "accesses unique identifiers": "accesses_unique_identifiers",
    "activities accessible to other apps": "activities_accessible_to_other_apps",
    "app is debuggable": "app_is_debuggable",
    "contains hard-coded cryptographic key": "contains_hard_coded_cryptographic_key",
    "contains native code": "contains_native_code",
    "contains potential hard-coded password": "contains_potential_hard_coded_password",  # pragma: allowlist secret
    "contains potential sql injection": "contains_potential_sql_injection",
    "contains reflection code": "contains_reflection_code",
    "creates blowfish key with weak length": "creates_blowfish_key_with_weak_length",
    "creates rsa keys with weak modulus length": "creates_rsa_keys_with_weak_modulus_length",
    "does not update security provider": "does_not_update_security_provider",
    "receivers accessible to other apps": "receivers_accessible_to_other_apps",
    "requests root access": "requests_root_access",
    "services accessible to other apps": "services_accessible_to_other_apps",
    "sms cve-2014-8610": "sms_cve_2014_8610",
    "source code is not obfuscated": "source_code_is_not_obfuscated",
    "uses sha1 hashing algorithm": "uses_sha1_hashing_algorithm",
    "weakly configured xml parser": "weakly_configured_xml_parser",
    "writes sensitive information to system log": "writes_sensitive_information_to_system_log",
    "uses spoofable values for authentication": "uses_spoofable_values_for_authentication",
    "copies sensitive information into the clipboard without user consent": (
        "copies_sensitive_information_into_clipboard_without_user_consent"
    ),
}
CODE_CHECK_SPECS = (
    {
        "check": "Accesses Unique Identifiers",
        "severity": "Medium",
        "compliance": "NIAP: FDP_DEC_EXT.1.1; FDP_DEC_EXT.1.2",
        "present_explanation": "The app accesses unique device or user identifiers.",
        "not_present_explanation": "The app does not access any unique identifiers.",
        "aliases": (),
    },
    {
        "check": "Activities Accessible to Other Apps",
        "severity": "High",
        "compliance": "OWASP: 2016-M1-Improper Platform Usage",
        "present_explanation": "One or more activities are exported or otherwise accessible to other apps.",
        "not_present_explanation": "No activities are exported, or access to all activities is restricted by use of permissions.",
        "aliases": ("unprotected exported activity",),
    },
    {
        "check": "App is Debuggable",
        "severity": "High",
        "compliance": "OWASP: 2016-M10-Extraneous Functionality",
        "present_explanation": (
            "The app is debuggable. A malicious actor with physical access to a device that has USB "
            "debugging enabled can attach a debugger to the app's process during execution. This is "
            "dangerous because it could expose sensitive information, enable reverse engineering, and "
            "allow the execution of arbitrary code."
        ),
        "not_present_explanation": "The app is not marked as debuggable based on the available manifest evidence.",
        "aliases": (),
    },
    {
        "check": "Contains Hard-coded Cryptographic Key",
        "severity": "High",
        "compliance": "OWASP: 2016-M5-Insufficient Cryptography; 2016-M9-Reverse Engineering",
        "present_explanation": "Potential hard-coded cryptographic key material was found in the app.",
        "not_present_explanation": "No hard-coded cryptographic keys were found in the app.",
        "aliases": ("contains hard-coded cryptographic key / credentials",),
    },
    {
        "check": "Contains Native Code",
        "severity": "Medium",
        "compliance": "OWASP: 2016-M7-Client Code Quality",
        "present_explanation": "The app loads native code libraries.",
        "not_present_explanation": "The app does not load native code libraries.",
        "aliases": (),
    },
    {
        "check": "Contains Potential Hard-coded Password",
        "severity": "High",
        "compliance": "OWASP: 2016-M9-Reverse Engineering",
        "present_explanation": "Potential hard-coded password material was found in the app.",
        "not_present_explanation": "No hard-coded passwords were found in the app.",
        "aliases": (),
    },
    {
        "check": "Contains Potential SQL Injection",
        "severity": "High",
        "compliance": "OWASP: 2016-M7-Client Code Quality; NIAP: FPT_API_EXT.2.1",
        "present_explanation": "Potential SQL injection behavior was found in the app.",
        "not_present_explanation": "No potential SQL injection vulnerabilities were found.",
        "aliases": (),
    },
    {
        "check": "Contains Reflection Code",
        "severity": "Medium",
        "compliance": "",
        "present_explanation": "The app contains Java reflection code.",
        "not_present_explanation": "The app does not contain Java reflection code.",
        "aliases": (),
    },
    {
        "check": "Creates Blowfish Key with Weak Length",
        "severity": "High",
        "compliance": "OWASP: 2016-M5-Insufficient Cryptography; NIAP: FCS_COP.1.1(1)",
        "present_explanation": "The app creates a Blowfish key with less than 128 bits in length.",
        "not_present_explanation": "The app does not create a Blowfish key with less than 128 bits in length.",
        "aliases": (),
    },
    {
        "check": "Creates RSA Keys with Weak Modulus Length",
        "severity": "High",
        "compliance": "OWASP: 2016-M5-Insufficient Cryptography; NIAP: FCS_CKM.1.1(1)",
        "present_explanation": "The app creates an RSA key with modulus length less than 1024 bits.",
        "not_present_explanation": "The app does not create an RSA key with modulus length less than 1024 bits.",
        "aliases": (),
    },
    {
        "check": "Does not Update Security Provider",
        "severity": "Medium",
        "compliance": "OWASP: 2016-M1-Improper Platform Usage; 2016-M5-Insufficient Cryptography",
        "present_explanation": "The app does not appear to use the dynamic GmsCore_OpenSSL Provider to keep the security provider updated.",
        "not_present_explanation": "The app uses the dynamic GmsCore_OpenSSL Provider to ensure that the device's security provider is always updated.",
        "aliases": (),
    },
    {
        "check": "Receivers Accessible to Other Apps",
        "severity": "High",
        "compliance": "OWASP: 2016-M1-Improper Platform Usage; NIAP: FMT_CFG_EXT.1.2",
        "present_explanation": "One or more receivers are exported or otherwise accessible to other apps.",
        "not_present_explanation": "The app does not contain receivers, no receivers are exported, or access to all exported receivers is restricted by use of permissions.",
        "aliases": ("unprotected exported receiver",),
    },
    {
        "check": "Requests Root Access",
        "severity": "High",
        "compliance": "OWASP: 2016-M8-Code Tampering",
        "present_explanation": "The app requests root access or superuser privileges. This allows the app to execute more advanced or potentially dangerous operations on the device.",
        "not_present_explanation": "No root-access or superuser execution requests were identified.",
        "aliases": (),
    },
    {
        "check": "Services Accessible to Other Apps",
        "severity": "High",
        "compliance": "OWASP: 2016-M1-Improper Platform Usage; NIAP: FMT_CFG_EXT.1.2",
        "present_explanation": "One or more services are exported or otherwise accessible to other apps.",
        "not_present_explanation": "The app does not contain services, no services are exported, or access to all services is restricted by use of permissions.",
        "aliases": ("unprotected exported service",),
    },
    {
        "check": "SMS CVE-2014-8610",
        "severity": "Medium",
        "compliance": "OWASP: 2016-M1-Improper Platform Usage",
        "present_explanation": "The app may be exposed to SMS CVE-2014-8610 based on the available messaging evidence.",
        "not_present_explanation": "The app does not send text messages or has the required SMS permission. It is protected from vulnerability CVE-2014-8610.",
        "aliases": (),
    },
    {
        "check": "Source Code is not Obfuscated",
        "severity": "Medium",
        "compliance": "OWASP: 2016-M9-Reverse Engineering",
        "present_explanation": "This app does not obfuscate its code by renaming classes, fields, and methods. This means it is possible for an adversary to reverse-engineer the application.",
        "not_present_explanation": "No strong evidence was found that the app source code is trivially non-obfuscated.",
        "aliases": (),
    },
    {
        "check": "Uses SHA1 Hashing Algorithm",
        "severity": "High",
        "compliance": "OWASP: 2016-M5-Insufficient Cryptography; NIAP: FCS_TUD_EXT.1.6",
        "present_explanation": "The app uses the SHA1 hashing algorithm, which is vulnerable to collision attacks.",
        "not_present_explanation": "No SHA1 hashing usage was identified in the available code-analysis evidence.",
        "aliases": (),
    },
    {
        "check": "Weakly Configured XML Parser",
        "severity": "Medium",
        "compliance": "OWASP: 2016-M7-Client Code Quality; NIAP: FPT_API_EXT.2.1",
        "present_explanation": "Potential weakly configured XML parsing behavior was found.",
        "not_present_explanation": "No potential weakly configured XML parsing is found.",
        "aliases": (),
    },
    {
        "check": "Writes Sensitive Information to System Log",
        "severity": "Medium",
        "compliance": "OWASP: 2016-M2-Insecure Data Storage; NIAP: FDP_DEC_EXT.1.2; HIPAA: 164.312(a)(2)(iv); GDPR: Articles 5, Article 25, Article 32",
        "present_explanation": "The app may write sensitive information to the system log.",
        "not_present_explanation": "This app was not observed to write sensitive information to the system log.",
        "aliases": (),
    },
    {
        "check": "Uses Spoofable Values for Authentication",
        "severity": "High",
        "compliance": "OWASP: 2016-M4-Insecure Authentication",
        "present_explanation": "The app authenticates using values that may be spoofed.",
        "not_present_explanation": "This app does not authenticate using values that can be spoofed.",
        "aliases": (),
    },
    {
        "check": "Copies Sensitive Information into the Clipboard Without User Consent",
        "severity": "Medium",
        "compliance": "OWASP: 2016-M2-Insecure Data Storage; HIPAA: 164.312(a)(2)(iv)",
        "present_explanation": "The app copies sensitive information into the clipboard without the user's consent.",
        "not_present_explanation": "This app does not copy sensitive information into the clipboard without the user's consent.",
        "aliases": (),
    },
)
STORAGE_CHECK_SPECS = (
    {
        "check": "Accesses External Storage",
        "severity": "Medium",
        "compliance": (
            "OWASP: 2016-M2-Insecure Data Storage; NIAP: FDP_DAR_EXT.1.1; "
            "HIPAA: 164.312(a)(2)(iv); GDPR: Articles 5, 25, 32"
        ),
        "present_explanation": (
            "The app accesses the external storage directory (SDCard), which "
            "can be accessed by any app on the device with the "
            "READ/WRITE_EXTERNAL_STORAGE permission."
        ),
        "not_present_explanation": ("No evidence was found that the app accesses shared external storage."),
        "aliases": ("app can read/write to external storage",),
    },
    {
        "check": "Authentication Credentials Not Protected with Android Keystore",
        "severity": "High",
        "compliance": (
            "OWASP: 2016-M2-Insecure Data Storage; NIAP: FDP_DAR_EXT.1.1; "
            "HIPAA: 164.312(a)(2)(iv); GDPR: Articles 5, 25, 32"
        ),
        "present_explanation": (
            "The app stores user authentication credentials (e.g. passwords, "
            "tokens) without using the Android Keystore system for "
            "hardware-backed protection."
        ),
        "not_present_explanation": (
            "No evidence was found that authentication credentials are stored without Android Keystore protection."
        ),
        "aliases": (),
    },
    {
        "check": "Sensitive Information Stored in World Readable or Writable File in Internal Storage",
        "severity": "High",
        "compliance": (
            "OWASP: 2016-M2-Insecure Data Storage; NIAP: FDP_DAR_EXT.1.1; "
            "FMT_CFG_EXT.1.2; FMT_MEC_EXT.1.1; HIPAA: 164.312(a)(2)(iv); "
            "GDPR: Articles 5, 25, 32"
        ),
        "present_explanation": (
            "The app stores sensitive information in internal storage using "
            "world-readable or world-writable file modes."
        ),
        "not_present_explanation": (
            "This app does not create world readable or writable files with "
            "sensitive information in its internal storage."
        ),
        "aliases": (),
    },
    {
        "check": "Sensitive Information Stored in External Storage",
        "severity": "High",
        "compliance": (
            "OWASP: 2016-M2-Insecure Data Storage; NIAP: FDP_DAR_EXT.1.1; "
            "FMT_CFG_EXT.1.2; FMT_MEC_EXT.1.1; HIPAA: 164.312(a)(2)(iv); "
            "GDPR: Articles 5, 25, 32"
        ),
        "present_explanation": (
            "The app stores sensitive information on the device in external "
            "storage, accessible from any app on the device with the "
            "READ_EXTERNAL_STORAGE permission."
        ),
        "not_present_explanation": (
            "No evidence was found that the app stores sensitive information in external storage."
        ),
        "aliases": (),
    },
    {
        "check": "Does not Prevent Screen Capture of Sensitive Information",
        "severity": "Medium",
        "compliance": "OWASP: 2016-M2-Insecure Data Storage",
        "present_explanation": (
            "The app does not prevent sensitive information on screen from "
            "being captured via screenshot or video by setting the "
            "FLAG_SECURE window layout parameter."
        ),
        "not_present_explanation": (
            "No evidence was found that the app leaves sensitive screens capturable without FLAG_SECURE protection."
        ),
        "aliases": (),
    },
)
RESILIENCE_CHECK_SPECS = (
    {
        "check": "Root Detection Missing",
        "severity": "Medium",
        "compliance": "",
        "present_explanation": "No root-detection or rooted-environment checks were identified in the available app evidence.",
        "not_present_explanation": "The app appears to contain root-detection or rooted-environment checks.",
        "aliases": (),
    },
    {
        "check": "Biometric / Local Authentication Bypass Possible",
        "severity": "Medium",
        "compliance": "",
        "present_explanation": "Biometric or local authentication use was identified without strong evidence of crypto-backed binding or equivalent hardening.",
        "not_present_explanation": "No biometric/local authentication flow was identified, or available evidence suggests crypto-backed hardening is present.",
        "aliases": (),
    },
)
NETWORK_CHECK_SPECS = (
    {
        "check": "Allows Cleartext Traffic for All Domains",
        "severity": "High",
        "compliance": (
            "OWASP: 2016-M3-Insecure Communication; NIAP: FTP_DIT_EXT.1.1; "
            "HIPAA: 164.312(e)(2)(ii); GDPR: Articles 5, Article 25, Article 32"
        ),
        "present_explanation": (
            "The app allows cleartext traffic for all domains by omitting a "
            "network security configuration file or explicitly allowing all "
            "cleartext traffic."
        ),
        "not_present_explanation": (
            "The app does not appear to allow cleartext traffic for all domains "
            "based on the available network configuration evidence."
        ),
        "aliases": (
            "network security configuration allows cleartext traffic",
            "network security config allows cleartext traffic for all domains",
            "clear text traffic is enabled for app",
        ),
    },
    {
        "check": "Contains HostnameVerifier That Accepts All Hostnames",
        "severity": "High",
        "compliance": "OWASP: 2016-M3-Insecure Communication; NIAP: FIA_X509_EXT.1.1",
        "present_explanation": (
            "A weak HostnameVerifier was found that accepts all hostnames, which "
            "can allow the app to trust unexpected TLS endpoints."
        ),
        "not_present_explanation": "No weak HostnameVerifiers are found.",
        "aliases": (),
    },
    {
        "check": "Contains X509TrustManager that Accepts All Certificates",
        "severity": "High",
        "compliance": "OWASP: 2016-M3-Insecure Communication; NIAP: FIA_X509_EXT.1.1",
        "present_explanation": (
            "A weak X509TrustManager was found that accepts all certificates, "
            "which can allow interception of TLS traffic."
        ),
        "not_present_explanation": "No weak X509TrustManagers are found.",
        "aliases": (),
    },
    {
        "check": "Does not Perform Certificate Pinning",
        "severity": "Medium",
        "compliance": "OWASP: 2016-M3-Insecure Communication; NIAP: FTP_DIT_EXT.1.1",
        "present_explanation": (
            "The app does not implement certificate pinning. Without certificate "
            "pinning, an attacker may be able to compromise the security of the "
            "app's TLS network communication using a rogue certificate."
        ),
        "not_present_explanation": (
            "The app implements certificate pinning or no lack of certificate pinning was identified in this scan."
        ),
        "aliases": (),
    },
    {
        "check": "Opens a Listening Port",
        "severity": "Medium",
        "compliance": "NIAP: FDP_NET_EXT.1.1",
        "present_explanation": (
            "The app opens a listening port on the device, which can increase "
            "the attack surface for local network or inter-app attacks."
        ),
        "not_present_explanation": "This app does not open a listening port on the device.",
        "aliases": (),
    },
    {
        "check": "Sensitive Cookies Lack Security Attributes",
        "severity": "Medium",
        "compliance": "OWASP: 2016-M4-Insecure Authentication",
        "present_explanation": (
            "The app receives sensitive cookies without required security "
            "attributes, which can weaken session protection."
        ),
        "not_present_explanation": (
            "This app does not receive sensitive cookies, such as authentication "
            "cookies, without security attributes, or does not receive any "
            "sensitive cookies."
        ),
        "aliases": (),
    },
    {
        "check": "Unnecessary Information Transmitted",
        "severity": "Low",
        "compliance": "GDPR: Article 23; NIAP: FDP_NET_EXT.1.1; FPR_ANO_EXT.1.1",
        "present_explanation": ("The app transmits unnecessary user or device information over the network."),
        "not_present_explanation": "This app does not send any unnecessary user or device information.",
        "aliases": (),
    },
    {
        "check": "Sensitive Information is Unencrypted in Transit",
        "severity": "High",
        "compliance": (
            "OWASP: 2016-M3-Insecure Communication; NIAP: FTP_DIT_EXT.1.1; "
            "HIPAA: 164.312(e)(2)(ii); GDPR: Articles 5, Article 25, Article 32"
        ),
        "present_explanation": (
            "This app sends sensitive information over the network without "
            "encryption. An adversary on the local network or on-path could "
            "easily capture this sensitive information."
        ),
        "not_present_explanation": (
            "No unencrypted transmission of sensitive information was identified in this scan."
        ),
        "aliases": (),
    },
    {
        "check": "Password is not Hashed in Transit",
        "severity": "High",
        "compliance": "",
        "present_explanation": (
            "This app does not hash the user's password before sending it over "
            "the network. This could expose the user's plaintext password to the "
            "recipient or to an adversary if the security of the connection is "
            "compromised. When sending a password over the network it is best "
            "practice to hash the password before sending it off the client "
            "device, and then to hash the result again once it reaches the server."
        ),
        "not_present_explanation": ("No evidence was found that the app sends unhashed passwords over the network."),
        "aliases": (),
    },
    {
        "check": "Weak Certificate Validation Enables MitM Attacks",
        "severity": "High",
        "compliance": (
            "OWASP: 2016-M3-Insecure Communication; NIAP: FIA_X509_EXT.1.1; "
            "HIPAA: 164.312(e)(2)(ii); GDPR: Articles 5, Article 25, Article 32"
        ),
        "present_explanation": (
            "The app is vulnerable to man-in-the-middle attacks that could "
            "compromise the confidentiality of some or all encrypted network "
            "communications due to flawed certificate validation. An attacker "
            "could exploit this flaw locally, using techniques such as ARP "
            "spoofing and evil twin Wi-Fi hotspots, or remotely using BGP "
            "hijacking or DNS cache poisoning."
        ),
        "not_present_explanation": (
            "No weak certificate-validation behavior leading to man-in-the-middle exposure was identified in this scan."
        ),
        "aliases": ("network security configuration allows user-installed cas",),
    },
)

IOS_CODE_CHECK_SPECS = (
    {
        "check": "Deprecated API - UIWebView",
        "severity": "Medium",
        "compliance": "MASVS-PLATFORM-2; MASTG-TEST-0076, -0078; MASTG-BEST-0032; legacy MSTG-CODE-3 (as observed)",
        "present_explanation": "Binary references the deprecated UIWebView component rather than WKWebView.",
        "not_present_explanation": "No references to the deprecated UIWebView component were found; the app uses WKWebView.",
        "confidence_caveat": None,
        "aliases": (),
    },
    {
        "check": "Insecure Nanopb Library",
        "severity": "High",
        "compliance": "MASVS-CODE-3; legacy MSTG-CODE-3 (as observed)",
        "present_explanation": "App bundles a known-vulnerable version of the Nanopb protobuf library.",
        "not_present_explanation": "App does not bundle a known-vulnerable version of the Nanopb protobuf library.",
        "confidence_caveat": None,
        "aliases": (),
    },
    {
        "check": "Insecure Serialization API - NSKeyedUnarchiver",
        "severity": "High",
        "compliance": (
            "MASVS-CODE-4; no confirmed v2 MASTG-TEST ID for NSKeyedUnarchiver specifically; "
            "legacy MSTG-CODE-4 (as observed)"
        ),
        "present_explanation": (
            "App uses NSKeyedUnarchiver's unsecure decoding path on untrusted data (i.e. decodeObject "
            "without a class allowlist, instead of decodeObjectOfClasses:forKey: or NSSecureCoding)."
        ),
        "not_present_explanation": (
            "App does not use NSKeyedUnarchiver's unsecure decoding path on untrusted data (i.e. "
            "decodeObject without a class allowlist, instead of decodeObjectOfClasses:forKey: or "
            "NSSecureCoding)."
        ),
        "confidence_caveat": (
            "Detected via symbol/selector-name presence; can't fully distinguish safe from unsafe usage "
            "without deeper analysis."
        ),
        "aliases": (),
    },
    {
        "check": "Missing ARC Binary Protections",
        "severity": "Medium",
        "compliance": (
            "MASVS-CODE-4; no confirmed v2 replacement for ARC specifically (MASTG-TEST-0087 deprecated -- "
            "its split successors 0228/0229 cover PIE/Stack Canary only); legacy MSTG-CODE-4"
        ),
        "present_explanation": (
            "ARC is not enabled -- the binary lacks Automatic Reference Counting, an exploit-mitigation "
            "mechanism against memory-corruption bugs."
        ),
        "not_present_explanation": (
            "ARC is enabled -- the binary is compiled with Automatic Reference Counting, an "
            "exploit-mitigation mechanism against memory-corruption bugs."
        ),
        "confidence_caveat": (
            "Inferred from Mach-O imported-function presence (_objc_release/_swift_release), not a direct "
            "compiler flag; absence is less reliable if imports are stripped or unavailable."
        ),
        "aliases": ("arc binary protections", "application utilizes arc binary protections"),
    },
    {
        "check": "Position-Independent Code (PIC) Not Enabled",
        "severity": "Medium",
        "compliance": "MASVS-CODE-4; MASTG-TEST-0228 (active -- supersedes deprecated 0087); legacy MSTG-CODE-4",
        "present_explanation": (
            "PIE is not enabled -- the binary is not position-independent, making ROP attacks easier to "
            "execute reliably."
        ),
        "not_present_explanation": (
            "PIE is enabled -- the binary is position-independent, making ROP attacks harder to execute reliably."
        ),
        "confidence_caveat": None,
        "aliases": ("pic binary protections", "application utilizes pic binary protections"),
    },
    {
        "check": "Stack Canaries Not Enabled",
        "severity": "Medium",
        "compliance": "MASVS-CODE-4; MASTG-TEST-0229 (active -- supersedes deprecated 0087); legacy MSTG-CODE-4",
        "present_explanation": (
            "A stack canary is not present -- stack buffer overflows overwriting the return address "
            "would not be caught before the function returns."
        ),
        "not_present_explanation": (
            "A stack canary is present -- stack buffer overflows overwriting the return address would "
            "be caught before the function returns."
        ),
        "confidence_caveat": (
            "Inferred from Mach-O imported-function presence (___stack_chk_fail and ___stack_chk_guard); "
            "absence is less reliable if imports are stripped or unavailable."
        ),
        "aliases": ("stack smashing protections", "application utilizes stack smashing protections"),
    },
    {
        "check": "Insecure API Usage in Binary",
        "severity": "Medium",
        "compliance": "MASVS-CODE-4; no confirmed v2 replacement (MASTG-TEST-0086 deprecated); legacy MSTG-CODE-8",
        "present_explanation": (
            "Binary references potentially dangerous C functions (e.g. fopen, memcpy, strcpy, strncpy, sscanf)."
        ),
        "not_present_explanation": (
            "No potentially dangerous C function references (e.g. fopen, memcpy, strcpy, strncpy, sscanf) were found."
        ),
        "confidence_caveat": (
            "Symbol presence confirms the function is linked, not necessarily invoked at runtime; "
            "confidence drops further if Symbols Stripped is true."
        ),
        "aliases": (),
    },
    {
        "check": "Usage of malloc Instead of calloc in Binary",
        "severity": "Medium",
        "compliance": (
            "MASVS-CODE-4; no confirmed v2 replacement (subsumed under deprecated MASTG-TEST-0086); legacy MSTG-CODE-8"
        ),
        "present_explanation": (
            "Binary uses malloc rather than calloc, which does not zero-initialize allocated memory."
        ),
        "not_present_explanation": "No use of malloc (in place of calloc) was found in the binary.",
        "confidence_caveat": "Same symbol-presence caveat as Insecure API Usage in Binary above.",
        "aliases": (),
    },
    {
        "check": "Application Encodes Data Using Insecure Cryptography",
        "severity": "High",
        "compliance": "MASVS-CRYPTO-1; legacy MSTG-CRYPTO-1",
        "present_explanation": "App encodes data using a weak or deprecated cryptographic algorithm.",
        "not_present_explanation": "App does not encode data using a weak or deprecated cryptographic algorithm.",
        "confidence_caveat": None,
        "aliases": (),
    },
    {
        "check": "Application Utilizes Insecure Cryptography",
        "severity": "High",
        "compliance": "MASVS-CRYPTO-1; legacy MSTG-CRYPTO-1",
        "present_explanation": "App uses a known-weak cryptographic primitive (e.g. DES, RC4, ECB mode).",
        "not_present_explanation": "App does not use a known-weak cryptographic primitive (e.g. DES, RC4, ECB mode).",
        "confidence_caveat": None,
        "aliases": (),
    },
    {
        "check": "PBKDF2 Iteration Count <10k",
        "severity": "Medium",
        "compliance": "MASVS-CRYPTO-1; legacy MSTG-CRYPTO-1",
        "present_explanation": ("Where PBKDF2 is used, the iteration count falls below the recommended minimum."),
        "not_present_explanation": (
            "Where PBKDF2 is used, the iteration count meets or exceeds the recommended minimum."
        ),
        "confidence_caveat": (
            "Not detectable via symbol/string scanning alone -- the iteration count is a constant "
            "argument that requires disassembly (e.g. radare2/Ghidra) to read; currently unverified."
        ),
        "aliases": (),
    },
    {
        "check": "Hardcoded API Keys within the Application Bundle",
        "severity": "High",
        "compliance": "MASVS-CRYPTO-2, MASVS-STORAGE-1; legacy MSTG-CRYPTO-2",
        "present_explanation": "A hardcoded API key was found bundled in the app package.",
        "not_present_explanation": "No hardcoded API keys were found bundled in the app package.",
        "confidence_caveat": None,
        "aliases": (),
    },
    {
        "check": "Potentially Insecure iOS Entitlements",
        "severity": "Medium",
        "compliance": "MASVS-PLATFORM-1, MASVS-RESILIENCE-2; legacy MSTG-PLATFORM-1",
        "present_explanation": (
            "One or more entitlements are flagged as risky (e.g. broadly-shared "
            "keychain-access-groups, get-task-allow enabled in a production build)."
        ),
        "not_present_explanation": (
            "No entitlements flagged as risky (e.g. broadly-shared keychain-access-groups, "
            "get-task-allow enabled in a production build) were found."
        ),
        "confidence_caveat": None,
        "aliases": (),
    },
)
IOS_NETWORK_CHECK_SPECS = (
    {
        "check": "App Transport Security (ATS) Disabled",
        "severity": "High",
        "compliance": "MASVS-NETWORK-1; MASTG-TEST-0322; legacy MSTG-NETWORK-1",
        "present_explanation": (
            "ATS is globally disabled via NSAllowsArbitraryLoads, allowing unsecured HTTP connections "
            "and skipping extended TLS checks even on HTTPS connections."
        ),
        "not_present_explanation": "ATS is not globally disabled; no NSAllowsArbitraryLoads override was found.",
        "confidence_caveat": None,
        "aliases": ("application transport security disabled",),
    },
    {
        "check": "Change Cipher Spec Injection Vulnerable OpenSSL Version",
        "severity": "High",
        "compliance": "MASVS-NETWORK-1, MASVS-CODE-3; legacy MSTG-NETWORK-1",
        "present_explanation": "App bundles an OpenSSL version vulnerable to CVE-2014-0224.",
        "not_present_explanation": "App does not bundle an OpenSSL version vulnerable to CVE-2014-0224.",
        "confidence_caveat": None,
        "aliases": (),
    },
    {
        "check": "Application Contains Deprecated FTP Functionality",
        "severity": "Medium",
        "compliance": "MASVS-NETWORK-1; MASTG-TEST-0323; legacy MSTG-NETWORK-1",
        "present_explanation": "App uses FTP for network transfers.",
        "not_present_explanation": "App does not use FTP for network transfers.",
        "confidence_caveat": None,
        "aliases": (),
    },
    {
        "check": "Application Contains Heartbleed Vulnerable OpenSSL Version",
        "severity": "High",
        "compliance": "MASVS-NETWORK-1, MASVS-CODE-3; legacy MSTG-NETWORK-1",
        "present_explanation": "App bundles an OpenSSL version vulnerable to Heartbleed (CVE-2014-0160).",
        "not_present_explanation": "App does not bundle an OpenSSL version vulnerable to Heartbleed (CVE-2014-0160).",
        "confidence_caveat": None,
        "aliases": (),
    },
    {
        "check": "Application Contains Insecure HTTP Traffic",
        "severity": "High",
        "compliance": "MASVS-NETWORK-1; MASTG-TEST-0321, -0322, -0323; legacy MSTG-NETWORK-1",
        "present_explanation": "App makes plaintext HTTP requests.",
        "not_present_explanation": "App does not make plaintext HTTP requests.",
        "confidence_caveat": None,
        "aliases": (),
    },
    {
        "check": "Application Selectively Disabled App Transport Security Protections",
        "severity": "Medium",
        "compliance": "MASVS-NETWORK-1; MASTG-TEST-0322; legacy MSTG-NETWORK-1",
        "present_explanation": (
            "App carves out per-domain ATS exceptions (NSExceptionDomains) that weaken transport security."
        ),
        "not_present_explanation": (
            "App does not carve out per-domain ATS exceptions (NSExceptionDomains) that weaken transport security."
        ),
        "confidence_caveat": None,
        "aliases": (),
    },
    {
        "check": "Cookie missing 'httpOnly' flag",
        "severity": "Medium",
        "compliance": "MASVS-NETWORK-1 (WebView cookies -> MASVS-PLATFORM-2); legacy MSTG-NETWORK-1",
        "present_explanation": "A cookie was set without the httpOnly attribute, allowing script access to its value.",
        "not_present_explanation": "No cookies were found set without the httpOnly attribute.",
        "confidence_caveat": (
            "No static artifact exists for WKWebView cookie attributes -- this requires dynamic analysis "
            "to confirm; treat as informational until verified at runtime."
        ),
        "aliases": (),
    },
    {
        "check": "Cookie missing 'Secure' flag",
        "severity": "Medium",
        "compliance": "MASVS-NETWORK-1; legacy MSTG-NETWORK-1",
        "present_explanation": (
            "A cookie was set without the Secure attribute, allowing transmission over an unencrypted channel."
        ),
        "not_present_explanation": "No cookies were found set without the Secure attribute.",
        "confidence_caveat": (
            "No static artifact exists for WKWebView cookie attributes -- this requires dynamic analysis "
            "to confirm; treat as informational until verified at runtime."
        ),
        "aliases": (),
    },
    {
        "check": "HTTP Cleartext Transmission of Advertiser ID",
        "severity": "High",
        "compliance": "MASVS-NETWORK-1, MASVS-PRIVACY-1; MASTG-TEST-0321; legacy MSTG-NETWORK-1",
        "present_explanation": "Advertiser ID is sent over an unencrypted HTTP connection.",
        "not_present_explanation": "Advertiser ID is not sent over an unencrypted HTTP connection.",
        "confidence_caveat": "Approximated via string/URL pattern matching with keyword proximity, not confirmed data flow.",
        "aliases": (),
    },
    {
        "check": "HTTP Cleartext Transmission of Device IMEI",
        "severity": "High",
        "compliance": "MASVS-NETWORK-1, MASVS-PRIVACY-1; MASTG-TEST-0321; legacy MSTG-NETWORK-1",
        "present_explanation": "Device identifier is sent over an unencrypted HTTP connection.",
        "not_present_explanation": "Device identifier is not sent over an unencrypted HTTP connection.",
        "confidence_caveat": "Approximated via string/URL pattern matching with keyword proximity, not confirmed data flow.",
        "aliases": (),
    },
    {
        "check": "HTTP Cleartext Transmission of GPS Latitude Coordinates",
        "severity": "High",
        "compliance": "MASVS-NETWORK-1, MASVS-PRIVACY-1; MASTG-TEST-0321; legacy MSTG-NETWORK-1",
        "present_explanation": "GPS latitude is sent over an unencrypted HTTP connection.",
        "not_present_explanation": "GPS latitude is not sent over an unencrypted HTTP connection.",
        "confidence_caveat": "Approximated via string/URL pattern matching with keyword proximity, not confirmed data flow.",
        "aliases": (),
    },
    {
        "check": "HTTP Cleartext Transmission of GPS Longitude Coordinates",
        "severity": "High",
        "compliance": "MASVS-NETWORK-1, MASVS-PRIVACY-1; MASTG-TEST-0321; legacy MSTG-NETWORK-1",
        "present_explanation": "GPS longitude is sent over an unencrypted HTTP connection.",
        "not_present_explanation": "GPS longitude is not sent over an unencrypted HTTP connection.",
        "confidence_caveat": "Approximated via string/URL pattern matching with keyword proximity, not confirmed data flow.",
        "aliases": (),
    },
    {
        "check": "HTTP Cleartext Transmission of Sensitive Data",
        "severity": "High",
        "compliance": "MASVS-NETWORK-1, MASVS-PRIVACY-1; MASTG-TEST-0321; legacy MSTG-NETWORK-1",
        "present_explanation": "Other sensitive data was found sent over an unencrypted HTTP connection.",
        "not_present_explanation": "No other sensitive data was found sent over an unencrypted HTTP connection.",
        "confidence_caveat": "Approximated via string/URL pattern matching with keyword proximity, not confirmed data flow.",
        "aliases": (),
    },
    {
        "check": "HTTP Cleartext Transmission of WiFi MAC Address",
        "severity": "High",
        "compliance": "MASVS-NETWORK-1, MASVS-PRIVACY-1; MASTG-TEST-0321; legacy MSTG-NETWORK-1",
        "present_explanation": "WiFi MAC address is sent over an unencrypted HTTP connection.",
        "not_present_explanation": "WiFi MAC address is not sent over an unencrypted HTTP connection.",
        "confidence_caveat": "Approximated via string/URL pattern matching with keyword proximity, not confirmed data flow.",
        "aliases": (),
    },
    {
        "check": "HTTPS Traffic URL Contains Device IMEI",
        "severity": "Medium",
        "compliance": "MASVS-PRIVACY-1, MASVS-NETWORK-1; legacy MSTG-NETWORK-1",
        "present_explanation": "Device IMEI is embedded in an HTTPS request URL.",
        "not_present_explanation": "Device IMEI is not embedded in an HTTPS request URL.",
        "confidence_caveat": "Approximated via string/URL pattern matching with keyword proximity, not confirmed data flow.",
        "aliases": (),
    },
    {
        "check": "HTTPS Traffic URL Contains Device's GPS Latitude",
        "severity": "Medium",
        "compliance": "MASVS-PRIVACY-1, MASVS-NETWORK-1; legacy MSTG-NETWORK-1",
        "present_explanation": "GPS latitude is embedded in an HTTPS request URL.",
        "not_present_explanation": "GPS latitude is not embedded in an HTTPS request URL.",
        "confidence_caveat": "Approximated via string/URL pattern matching with keyword proximity, not confirmed data flow.",
        "aliases": (),
    },
    {
        "check": "HTTPS Traffic URL Contains Device's GPS Longitude",
        "severity": "Medium",
        "compliance": "MASVS-PRIVACY-1, MASVS-NETWORK-1; legacy MSTG-NETWORK-1",
        "present_explanation": "GPS longitude is embedded in an HTTPS request URL.",
        "not_present_explanation": "GPS longitude is not embedded in an HTTPS request URL.",
        "confidence_caveat": "Approximated via string/URL pattern matching with keyword proximity, not confirmed data flow.",
        "aliases": (),
    },
    {
        "check": "HTTPS Traffic URL Contains Sensitive Data",
        "severity": "Medium",
        "compliance": "MASVS-PRIVACY-1, MASVS-NETWORK-1; legacy MSTG-NETWORK-1",
        "present_explanation": "Other sensitive data was found embedded in an HTTPS request URL.",
        "not_present_explanation": "No other sensitive data was found embedded in an HTTPS request URL.",
        "confidence_caveat": "Approximated via string/URL pattern matching with keyword proximity, not confirmed data flow.",
        "aliases": (),
    },
    {
        "check": "HTTPS Traffic URL Contains WiFi MAC Address",
        "severity": "Medium",
        "compliance": "MASVS-PRIVACY-1, MASVS-NETWORK-1; legacy MSTG-NETWORK-1",
        "present_explanation": "WiFi MAC address is embedded in an HTTPS request URL.",
        "not_present_explanation": "WiFi MAC address is not embedded in an HTTPS request URL.",
        "confidence_caveat": "Approximated via string/URL pattern matching with keyword proximity, not confirmed data flow.",
        "aliases": (),
    },
    {
        "check": "Insecure TLS configuration",
        "severity": "High",
        "compliance": "MASVS-NETWORK-1; MASTG-TEST-0065-0067; legacy MSTG-NETWORK-1",
        "present_explanation": "One or more weak TLS protocol versions or cipher suites were configured.",
        "not_present_explanation": "No weak TLS protocol versions or cipher suites were configured.",
        "confidence_caveat": (
            "Detected via string scan for TLS version constants; may miss configuration set "
            "programmatically through other means."
        ),
        "aliases": (),
    },
    {
        "check": "Certificate Pinning Not Implemented",
        "severity": "Medium",
        "compliance": (
            "MASVS-NETWORK-2; no confirmed v2 replacement (MASTG-TEST-0068 deprecated); legacy "
            "MSTG-NETWORK-2 (as observed)"
        ),
        "present_explanation": (
            "App does not implement certificate or public-key pinning. Without pinning, a rogue "
            "CA-issued certificate could be used to intercept traffic."
        ),
        "not_present_explanation": "App implements certificate or public-key pinning.",
        "confidence_caveat": None,
        "aliases": ("application utilizes certificate pinning protections",),
    },
)
IOS_DATA_CHECK_SPECS = (
    {
        "check": "Application Utilizes Deprecated Keychain Attributes",
        "severity": "Medium",
        "compliance": "MASVS-STORAGE-1; MASTG-TEST-0052; MASTG-KNOW-0057; legacy MSTG-STORAGE-1",
        "present_explanation": "App uses a deprecated Keychain accessibility attribute.",
        "not_present_explanation": "App does not use a deprecated Keychain accessibility attribute.",
        "confidence_caveat": "Detected via constant-symbol presence; confidence drops if Symbols Stripped is true.",
        "aliases": (),
    },
    {
        "check": "Local Data Exposure: Advertiser ID Stored Insecurely",
        "severity": "High",
        "compliance": "MASVS-STORAGE-1; MASTG-TEST-0052, -0300-0302; legacy MSTG-STORAGE-1",
        "present_explanation": "Advertiser ID is written to an unprotected on-device storage location.",
        "not_present_explanation": "Advertiser ID is not written to an unprotected on-device storage location.",
        "confidence_caveat": "Approximated via storage-API symbol presence near PII-keyword strings, not confirmed data flow.",
        "aliases": (),
    },
    {
        "check": "Local Data Exposure: Device IMEI Stored Insecurely",
        "severity": "High",
        "compliance": "MASVS-STORAGE-1; MASTG-TEST-0052, -0300-0302; legacy MSTG-STORAGE-1",
        "present_explanation": "Device IMEI is written to an unprotected on-device storage location.",
        "not_present_explanation": "Device IMEI is not written to an unprotected on-device storage location.",
        "confidence_caveat": "Approximated via storage-API symbol presence near PII-keyword strings, not confirmed data flow.",
        "aliases": (),
    },
    {
        "check": "Local Data Exposure: Global Write Permissions (Source Code Only)",
        "severity": "High",
        "compliance": "MASVS-STORAGE-1, MASVS-PLATFORM-1; MASTG-TEST-0052; legacy MSTG-STORAGE-1",
        "present_explanation": "An app-created file has world-writable permissions.",
        "not_present_explanation": "No app-created file has world-writable permissions.",
        "confidence_caveat": "Approximated via storage-API symbol presence near PII-keyword strings, not confirmed data flow.",
        "aliases": (),
    },
    {
        "check": "Local Data Exposure: GPS Latitude Stored Insecurely",
        "severity": "High",
        "compliance": "MASVS-STORAGE-1; MASTG-TEST-0052, -0300-0302; legacy MSTG-STORAGE-1",
        "present_explanation": "GPS latitude is written to an unprotected on-device storage location.",
        "not_present_explanation": "GPS latitude is not written to an unprotected on-device storage location.",
        "confidence_caveat": "Approximated via storage-API symbol presence near PII-keyword strings, not confirmed data flow.",
        "aliases": (),
    },
    {
        "check": "Local Data Exposure: GPS Longitude Stored Insecurely",
        "severity": "High",
        "compliance": "MASVS-STORAGE-1; MASTG-TEST-0052, -0300-0302; legacy MSTG-STORAGE-1",
        "present_explanation": "GPS longitude is written to an unprotected on-device storage location.",
        "not_present_explanation": "GPS longitude is not written to an unprotected on-device storage location.",
        "confidence_caveat": "Approximated via storage-API symbol presence near PII-keyword strings, not confirmed data flow.",
        "aliases": (),
    },
    {
        "check": "Local Data Exposure: Insecure Hardcoded API Keys",
        "severity": "High",
        "compliance": "MASVS-STORAGE-1, MASVS-CRYPTO-2; MASTG-TEST-0052; legacy MSTG-STORAGE-1",
        "present_explanation": "A hardcoded API key was found persisted to unprotected on-device storage.",
        "not_present_explanation": "No hardcoded API key was found persisted to unprotected on-device storage.",
        "confidence_caveat": "Source findings identify data reaching storage; IPA-only findings are triage signals based on co-occurring symbols and strings and require source or runtime confirmation.",
        "aliases": (),
    },
    {
        "check": "Local Data Exposure: Insecure Hardcoded Passwords",
        "severity": "High",
        "compliance": "MASVS-STORAGE-1; MASTG-TEST-0052; legacy MSTG-STORAGE-1",
        "present_explanation": "A hardcoded password was found persisted to unprotected on-device storage.",
        "not_present_explanation": "No hardcoded password was found persisted to unprotected on-device storage.",
        "confidence_caveat": "Source findings identify data reaching storage; IPA-only findings are triage signals based on co-occurring symbols and strings and require source or runtime confirmation.",
        "aliases": (),
    },
    {
        "check": "Local Data Exposure: Sensitive Values Stored Insecurely",
        "severity": "High",
        "compliance": "MASVS-STORAGE-1; MASTG-TEST-0052; legacy MSTG-STORAGE-1",
        "present_explanation": "Another sensitive value was found persisted to unprotected on-device storage.",
        "not_present_explanation": "No other sensitive value was found persisted to unprotected on-device storage.",
        "confidence_caveat": "Source findings identify data reaching storage; IPA-only findings are triage signals based on co-occurring symbols and strings and require source or runtime confirmation.",
        "aliases": (),
    },
    {
        "check": "Local Data Exposure: WiFi IP Address Stored Insecurely",
        "severity": "High",
        "compliance": "MASVS-STORAGE-1; MASTG-TEST-0052; legacy MSTG-STORAGE-1",
        "present_explanation": "WiFi IP address is written to an unprotected on-device storage location.",
        "not_present_explanation": "WiFi IP address is not written to an unprotected on-device storage location.",
        "confidence_caveat": "Source findings identify data reaching storage; IPA-only findings are triage signals based on co-occurring symbols and strings and require source or runtime confirmation.",
        "aliases": (),
    },
    {
        "check": "Local Data Exposure: WiFi MAC Address Stored Insecurely",
        "severity": "High",
        "compliance": "MASVS-STORAGE-1; MASTG-TEST-0052; legacy MSTG-STORAGE-1",
        "present_explanation": "WiFi MAC address is written to an unprotected on-device storage location.",
        "not_present_explanation": "WiFi MAC address is not written to an unprotected on-device storage location.",
        "confidence_caveat": "Approximated via storage-API symbol presence near PII-keyword strings, not confirmed data flow.",
        "aliases": (),
    },
    {
        "check": "Sensitive Values Stored in Plaintext Within the Keychain",
        "severity": "High",
        "compliance": "MASVS-STORAGE-1; MASTG-TEST-0052; MASTG-KNOW-0057; legacy MSTG-STORAGE-1",
        "present_explanation": "A Keychain item stores a sensitive value without additional protection.",
        "not_present_explanation": "No Keychain item stores a sensitive value without additional protection.",
        "confidence_caveat": "Detected via Keychain API usage pattern, not a direct read of stored values.",
        "aliases": (),
    },
    {
        "check": "Sensitive Data Stored in User Defaults",
        "severity": "High",
        "compliance": "MASVS-STORAGE-1; MASTG-TEST-0300-0302; MASTG-KNOW-0093; legacy MSTG-STORAGE-1",
        "present_explanation": "Sensitive data was found written to the app's local User Defaults preferences storage.",
        "not_present_explanation": (
            "No sensitive data was found written to the app's local User Defaults preferences storage."
        ),
        "confidence_caveat": (
            "Source findings identify a User Defaults write; IPA-only findings are triage signals based on "
            "co-occurring symbols and strings and require source or runtime confirmation."
        ),
        "aliases": (),
    },
    {
        "check": "Local Data Exposure: Advertiser ID Logged Insecurely",
        "severity": "Medium",
        "compliance": "MASVS-STORAGE-2; legacy MSTG-STORAGE-2 (as observed)",
        "present_explanation": (
            "Advertiser ID is written to the device console/log, which other apps or a connected debugger can read."
        ),
        "not_present_explanation": "Advertiser ID is not written to the device console/log.",
        "confidence_caveat": (
            "Source findings identify a value reaching a logging call; IPA-only findings are triage signals based on "
            "co-occurring symbols and strings and require source or runtime confirmation."
        ),
        "aliases": (),
    },
    {
        "check": "Local Data Exposure: Device IMEI Logged Insecurely",
        "severity": "Medium",
        "compliance": "MASVS-STORAGE-2; legacy MSTG-STORAGE-2",
        "present_explanation": "Device IMEI is written to the device console/log.",
        "not_present_explanation": "Device IMEI is not written to the device console/log.",
        "confidence_caveat": (
            "Source findings identify a value reaching a logging call; IPA-only findings are triage signals based on "
            "co-occurring symbols and strings and require source or runtime confirmation."
        ),
        "aliases": (),
    },
    {
        "check": "Local Data Exposure: GPS Latitude Logged Insecurely",
        "severity": "Medium",
        "compliance": "MASVS-STORAGE-2; legacy MSTG-STORAGE-2",
        "present_explanation": "GPS latitude is written to the device console/log.",
        "not_present_explanation": "GPS latitude is not written to the device console/log.",
        "confidence_caveat": (
            "Detected via logging-API symbol presence near PII-keyword strings, not a confirmed log-output capture."
        ),
        "aliases": (),
    },
    {
        "check": "Local Data Exposure: GPS Longitude Logged Insecurely",
        "severity": "Medium",
        "compliance": "MASVS-STORAGE-2; legacy MSTG-STORAGE-2",
        "present_explanation": "GPS longitude is written to the device console/log.",
        "not_present_explanation": "GPS longitude is not written to the device console/log.",
        "confidence_caveat": (
            "Detected via logging-API symbol presence near PII-keyword strings, not a confirmed log-output capture."
        ),
        "aliases": (),
    },
    {
        "check": "Local Data Exposure: Sensitive Data Logged Insecurely",
        "severity": "Medium",
        "compliance": "MASVS-STORAGE-2; legacy MSTG-STORAGE-2",
        "present_explanation": "Other sensitive data is written to the device console/log.",
        "not_present_explanation": "No other sensitive data is written to the device console/log.",
        "confidence_caveat": (
            "Source findings identify a value reaching a logging call; IPA-only findings are triage signals based on "
            "co-occurring symbols and strings and require source or runtime confirmation."
        ),
        "aliases": (),
    },
    {
        "check": "Local Data Exposure: Sensitive Values Stored in Memory",
        "severity": "Medium",
        "compliance": "MASVS-STORAGE-2; legacy MSTG-STORAGE-2",
        "present_explanation": (
            "A sensitive value was found retained in memory longer than necessary (e.g. not zeroed after use)."
        ),
        "not_present_explanation": (
            "No sensitive value was found retained in memory longer than necessary (e.g. not zeroed after use)."
        ),
        "confidence_caveat": (
            "Detected via logging-API symbol presence near PII-keyword strings, not a confirmed log-output capture."
        ),
        "aliases": (),
    },
    {
        "check": "Local Data Exposure: WiFi MAC Address Logged Insecurely",
        "severity": "Medium",
        "compliance": "MASVS-STORAGE-2; legacy MSTG-STORAGE-2",
        "present_explanation": "WiFi MAC address is written to the device console/log.",
        "not_present_explanation": "WiFi MAC address is not written to the device console/log.",
        "confidence_caveat": (
            "Source findings identify a value reaching a logging call; IPA-only findings are triage signals based on "
            "co-occurring symbols and strings and require source or runtime confirmation. BSSID can identify an "
            "access point rather than the device's own MAC address."
        ),
        "aliases": (),
    },
    {
        "check": "Sensitive Data Exposed Through Device Keyboard Cache (Source Code Only)",
        "severity": "Medium",
        "compliance": "MASVS-STORAGE-2; legacy MSTG-STORAGE-2",
        "present_explanation": (
            "One or more sensitive input fields explicitly enable autocorrection or spell checking, or disable "
            "secure text entry."
        ),
        "not_present_explanation": (
            "No sensitive input fields with an explicitly unsafe keyboard configuration were identified."
        ),
        "confidence_caveat": "Source-code-only detection of explicit unsafe input settings; IPA-only scans are not assessed.",
        "aliases": (),
    },
)
_IOS_RETIRED_DATA_CHECK_NAMES = {
    "Local Data Exposure: WiFi MAC Address Stored Insecurely",
    "Local Data Exposure: Sensitive Values Stored in Memory",
}
IOS_DATA_CHECK_SPECS = tuple(
    {
        **spec,
        **(
            {
                "check": "Local Data Exposure: IMEI-Labeled Value Stored Insecurely",
                "present_explanation": "An IMEI-labeled value is written to an unprotected on-device storage location.",
                "not_present_explanation": "No IMEI-labeled value is written to an unprotected on-device storage location.",
            }
            if spec["check"] == "Local Data Exposure: Device IMEI Stored Insecurely"
            else {}
        ),
        **(
            {
                "check": "Local Data Exposure: Location Data Stored Insecurely",
                "present_explanation": "Location data is written to an unprotected on-device storage location.",
                "not_present_explanation": "Location data is not written to an unprotected on-device storage location.",
                "confidence_caveat": (
                    "Source findings identify data reaching storage; IPA-only findings are triage signals based on "
                    "co-occurring symbols and strings and require source or runtime confirmation."
                ),
            }
            if spec["check"] == "Local Data Exposure: GPS Latitude Stored Insecurely"
            else {}
        ),
        **(
            {
                "check": "Keychain Items Accessible After First Unlock",
                "severity": "Medium",
                "present_explanation": "One or more Keychain items are configured to be accessible after the first device unlock.",
                "not_present_explanation": "No Keychain items configured to be accessible after the first device unlock were identified.",
                "confidence_caveat": "Detected from Keychain accessibility configuration, not a direct read of stored values.",
            }
            if spec["check"] == "Sensitive Values Stored in Plaintext Within the Keychain"
            else {}
        ),
        **(
            {
                "check": "Local Data Exposure: Location Data Logged Insecurely",
                "present_explanation": "Location data is written to the device console/log.",
                "not_present_explanation": "Location data is not written to the device console/log.",
                "confidence_caveat": (
                    "Source findings identify a value reaching a logging call; IPA-only findings are triage signals based "
                    "on co-occurring symbols and strings and require source or runtime confirmation."
                ),
            }
            if spec["check"] == "Local Data Exposure: GPS Latitude Logged Insecurely"
            else {}
        ),
    }
    for spec in IOS_DATA_CHECK_SPECS
    if spec["check"] not in _IOS_RETIRED_DATA_CHECK_NAMES
    and spec["check"] != "Local Data Exposure: GPS Longitude Stored Insecurely"
    and spec["check"] != "Local Data Exposure: GPS Longitude Logged Insecurely"
)

IOS_RESILIENCE_CHECK_SPECS = (
    {
        "check": "Biometric / Local Authentication Bypass Possible",
        "severity": "Medium",
        "compliance": (
            "MASVS-AUTH-2; MASTG-TEST-0266-0271 (active -- supersede deprecated 0064); legacy MSTG-AUTH-2 (as observed)"
        ),
        "present_explanation": (
            "A biometric/local authentication flow was identified without strong evidence of "
            "crypto-backed binding (Secure Enclave/kSecAccessControl) or equivalent hardening."
        ),
        "not_present_explanation": (
            "No biometric/local authentication flow was identified, or the flow present is backed by "
            "the Secure Enclave (LAContext + kSecAccessControl) rather than a spoofable boolean check."
        ),
        "confidence_caveat": "Detected via API-usage pattern, not a confirmed bypass test.",
        "aliases": (),
    },
    {
        "check": "Components Contain Debug Symbols",
        "severity": "Medium",
        "compliance": "MASVS-RESILIENCE-3; MASTG-TEST-0219 (active -- supersedes deprecated 0083); legacy MSTG-RESILIENCE-3",
        "present_explanation": (
            "Debug symbols were not stripped from the shipped binary, making static analysis and "
            "reverse engineering easier."
        ),
        "not_present_explanation": "Debug symbols were stripped from the shipped binary.",
        "confidence_caveat": None,
        "aliases": (),
    },
)
IPA_BINARY_PROTECTION_SPECS = (
    {
        "protection": "NX",
        "true_severity": "Info",
        "true_description": (
            "The binary has the NX bit set. This marks a memory page non-executable, making "
            "attacker-injected shellcode non-executable."
        ),
        "false_severity": "High",
        "false_description": (
            "The binary has the NX bit unset. This marks a memory page executable, allowing an "
            "attacker to point to shellcode in memory and exposing the binary to code-execution attacks."
        ),
    },
    {
        "protection": "PIE",
        "true_severity": "Info",
        "true_description": (
            "The binary is built with -fPIC, enabling position-independent code. This makes ROP "
            "attacks much harder to execute reliably."
        ),
        "false_severity": "High",
        "false_description": (
            "The binary is built without the Position Independent Executable (PIE) flag. This makes "
            "ROP attacks easier to execute reliably."
        ),
    },
    {
        "protection": "Stack Canary",
        "true_severity": "Info",
        "true_description": (
            "A stack canary value is added so that a stack buffer overflow overwriting the return "
            "address is detected before the function returns."
        ),
        "false_severity": "High",
        "false_description": (
            "No stack canary value is added to the stack. This binary may be susceptible to a stack "
            "buffer overflow attack overwriting the return address undetected."
        ),
    },
    {
        "protection": "ARC",
        "true_severity": "Info",
        "true_description": (
            "The binary is compiled with Automatic Reference Counting, an exploit-mitigation "
            "mechanism against memory-corruption vulnerabilities."
        ),
        "false_severity": "Medium",
        "false_description": (
            "The binary is not compiled with Automatic Reference Counting. ARC is a compiler feature "
            "that provides automatic memory management of Objective-C objects and helps prevent "
            "memory-corruption vulnerabilities."
        ),
    },
    {
        "protection": "RPATH",
        "true_severity": "Medium",
        "true_description": (
            "The binary has a Runpath Search Path (@rpath) set. In certain cases an attacker can "
            "abuse this to run an arbitrary executable for code execution or privilege escalation."
        ),
        "false_severity": "Info",
        "false_description": "The binary does not have a Runpath Search Path (@rpath) set.",
    },
    {
        "protection": "Code Signature",
        "true_severity": "Info",
        "true_description": "This binary has a code signature.",
        "false_severity": "High",
        "false_description": "This binary does not have a valid code signature.",
    },
    {
        "protection": "Encrypted",
        "true_severity": "Info",
        "true_description": "This binary is encrypted (FairPlay).",
        "false_severity": "Medium",
        "false_description": (
            "This binary is not encrypted (FairPlay). An unencrypted binary is easier to statically "
            "analyze and reverse-engineer."
        ),
    },
    {
        "protection": "Symbols Stripped",
        "true_severity": "Info",
        "true_description": (
            "Debug symbols are stripped from the binary, making static analysis and reverse engineering more difficult."
        ),
        "false_severity": "Medium",
        "false_description": (
            "Debug symbols are available. Strip them in build settings (Strip Debug Symbols During "
            "Copy / Deployment Postprocessing / Strip Linked Product, all set to Yes) before shipping."
        ),
    },
)

# Vulnerability categories excluded from the report entirely (per request:
# Authentication, Cryptography, and Platform are dropped from the output
# regardless of what's present in the source data file).
EXCLUDED_VULN_SECTIONS = {"authentication", "cryptography", "platform"}

# Path to the generic placeholder app-icon image used on the cover page
# when app_info.icon_path isn't provided.
PLACEHOLDER_ICON_PATH = BASE_DIR / "assets" / "placeholder_icon.png"
REPORT_BRAND_ICON_PATH = BASE_DIR / "assets" / "PhoenixShield.png"


def risk_badge(rating, label=None):
    from markupsafe import Markup

    key = (rating or "").strip().lower()
    css_class = {
        "critical": "badge-critical",
        "high": "badge-high",
        "medium": "badge-medium",
        "low": "badge-low",
        "info": "badge-info",
        "secure hotspot": "badge-secure",
        "secure": "badge-secure",
        "hotspot": "badge-hotspot",
        "variable": "badge-variable",
        "n/a": "badge-na",
        "dangerous": "badge-high",
        "normal": "badge-info",
    }.get(key, "badge-info")
    text = label if label else rating
    return Markup(f'<span class="badge {css_class}">{text}</span>')


def result_badge(result):
    from markupsafe import Markup

    key = (result or "").strip().lower()
    css_class = "badge-present" if key == "present" else "badge-notpresent"
    return Markup(f'<span class="badge {css_class}">{result}</span>')


def make_overall_risk_polar_chart(risk_summary):
    """Single polar-area (Nightingale rose) chart with one wedge per area of
    concern in risk_summary (e.g. Code Vulnerability, Data Storage,
    Networking, Resilience); wedge radius encodes Low/Medium/High and color
    matches the severity. Scales automatically to however many categories
    are present in risk_summary, so a 3-category and a 4-category report
    both render correctly with the same code."""
    import matplotlib
    import numpy as np

    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    # Preferred display order; any keys not listed here are appended in
    # whatever order they appear in the data.
    preferred_order = ["code_vulnerability", "data_storage", "networking", "resilience"]
    keys = [k for k in preferred_order if k in risk_summary]
    keys += [k for k in risk_summary if k not in keys]

    def pretty_label(key):
        words = key.replace("_", " ").split()
        # Two-word labels wrap onto two lines to match the original layout;
        # longer/shorter labels are left on one line.
        if len(words) == 2:
            return "\n".join(w.capitalize() for w in words)
        return " ".join(w.capitalize() for w in words)

    categories = [(pretty_label(k), risk_summary.get(k, "Low")) for k in keys]

    n = len(categories)
    theta = np.linspace(0.0, 2 * np.pi, n, endpoint=False) + (np.pi / 2)
    width = (2 * np.pi / n) * 0.92

    radii = []
    colors = []
    labels = []
    for label, level in categories:
        key = (level or "low").strip().lower()
        radii.append(RISK_LEVEL_ORDER.get(key, 1))
        colors.append(RISK_LEVEL_COLOR.get(key, "#2980b9"))
        labels.append(label)

    fig = plt.figure(figsize=(5.6, 4.8))
    ax = fig.add_subplot(111, projection="polar")
    ax.set_theta_zero_location("N")
    bars = ax.bar(theta, radii, width=width, color=colors, alpha=0.85, edgecolor="white", linewidth=2, bottom=0)

    ax.set_ylim(0, 4.3)
    ax.set_yticks([1, 2, 3])
    ax.set_yticklabels(["Low", "Medium", "High"], fontsize=7.5, color="#888")
    for t in ax.get_yticklabels():
        t.set_bbox(dict(facecolor="white", edgecolor="none", pad=1, alpha=0.85))
    ax.set_rlabel_position(200)
    ax.set_xticks(theta)
    ax.set_xticklabels(labels, fontsize=10, fontweight="bold", color="#16233c")
    ax.tick_params(axis="x", pad=14)
    ax.spines["polar"].set_color("#dddddd")
    ax.grid(color="#dddddd", linewidth=0.7)
    ax.set_facecolor("none")
    fig.patch.set_alpha(0)

    for angle, radius, level in zip(theta, radii, [c[1] for c in categories]):
        label_r = max(radius - 0.55, 0.6)
        ax.text(angle, label_r, level.title(), ha="center", va="center", fontsize=9, fontweight="bold", color="white")

    buf = io.BytesIO()
    fig.savefig(buf, format="png", dpi=200, bbox_inches="tight", transparent=True)
    plt.close(fig)
    buf.seek(0)
    return base64.b64encode(buf.read()).decode("ascii")


def build_charts(data):
    rs = data.get("risk_summary", {})
    return {"overall_risk_polar": make_overall_risk_polar_chart(rs)}


def get_app_icon_data_uri(data):
    """Return a data: URI for the app icon — the provided icon_path if set
    and readable, otherwise the generic placeholder icon."""
    icon_path = (data.get("app_info", {}) or {}).get("icon_path") or ""
    path = Path(icon_path) if icon_path else None
    if path and path.is_file():
        target = path
    else:
        target = PLACEHOLDER_ICON_PATH
    return _image_file_to_data_uri(target)


def get_report_brand_icon_data_uri() -> str:
    """Return a data: URI for the phoenix brand icon shown on the cover."""
    target = REPORT_BRAND_ICON_PATH if REPORT_BRAND_ICON_PATH.is_file() else PLACEHOLDER_ICON_PATH
    return _image_file_to_data_uri(target)


def _image_file_to_data_uri(target: Path) -> str:
    ext = target.suffix.lstrip(".").lower() or "png"
    mime = "jpeg" if ext in ("jpg", "jpeg") else ext
    encoded = base64.b64encode(target.read_bytes()).decode("ascii")
    return f"data:image/{mime};base64,{encoded}"


def load_report_data(input_data: dict[str, Any] | Path | str) -> dict[str, Any]:
    if isinstance(input_data, dict):
        data = copy.deepcopy(input_data)
    else:
        data = json.loads(Path(input_data).read_text(encoding="utf-8"))

    return _normalize_report_data(data)


def generate_report(
    input_data: dict[str, Any] | Path | str,
    output_path: Path | str,
    show_confidence_caveats: bool = False,
) -> Path:
    _configure_weasyprint_library_path()
    from jinja2 import Environment, FileSystemLoader
    from weasyprint import HTML

    data = load_report_data(input_data)
    resolved_output_path = Path(output_path)

    css_text = (TEMPLATES_DIR / "style.css").read_text(encoding="utf-8")
    charts = build_charts(data)
    app_icon_uri = get_app_icon_data_uri(data)
    phoenix_brand_icon_uri = get_report_brand_icon_data_uri()

    env = Environment(loader=FileSystemLoader(str(TEMPLATES_DIR)))
    env.globals["risk_badge"] = risk_badge
    env.globals["result_badge"] = result_badge

    template = env.get_template("report.html.jinja")
    html_out = template.render(
        data=data,
        css=css_text,
        charts=charts,
        app_icon_uri=app_icon_uri,
        phoenix_brand_icon_uri=phoenix_brand_icon_uri,
        show_confidence_caveats=show_confidence_caveats,
    )

    resolved_output_path.parent.mkdir(parents=True, exist_ok=True)
    HTML(string=html_out, base_url=str(BASE_DIR)).write_pdf(str(resolved_output_path))
    print(f"Wrote {resolved_output_path}")
    return resolved_output_path


def _configure_weasyprint_library_path() -> None:
    if sys.platform != "darwin":
        return

    known_library_dirs = [Path("/opt/homebrew/lib"), Path("/usr/local/lib")]
    existing_dirs = [str(path) for path in known_library_dirs if path.is_dir()]
    if not existing_dirs:
        return

    current = os.environ.get("DYLD_FALLBACK_LIBRARY_PATH", "")
    current_parts = [part for part in current.split(":") if part]
    merged_parts: list[str] = []
    for part in [*existing_dirs, *current_parts]:
        if part not in merged_parts:
            merged_parts.append(part)
    os.environ["DYLD_FALLBACK_LIBRARY_PATH"] = ":".join(merged_parts)


def _is_ios_platform(data: dict[str, Any]) -> bool:
    meta = data.get("meta") if isinstance(data.get("meta"), dict) else {}
    return str(meta.get("platform") or "").strip().lower() == "ios"


def _normalize_report_data(data: dict[str, Any]) -> dict[str, Any]:
    is_ios = _is_ios_platform(data)
    base_template = _ios_blank_template() if is_ios else _blank_template()
    report_data = _merge_nested(base_template, data)

    if is_ios:
        _canonicalize_ios_code_section(report_data)
        _canonicalize_ios_network_section(report_data)
        _canonicalize_ios_data_section(report_data)
        _canonicalize_ios_resilience_section(report_data)
        _apply_ios_derived_checks(report_data)
        _canonicalize_ios_binary_protections(report_data)
        _normalize_ios_url_schemes(report_data)
        section_to_area = IOS_SECTION_TO_AREA
    else:
        _canonicalize_code_section(report_data)
        _canonicalize_storage_section(report_data)
        _canonicalize_network_section(report_data)
        _canonicalize_resilience_section(report_data)
        _apply_derived_vulnerability_checks(report_data)
        section_to_area = SECTION_TO_AREA

    _add_permission_display_names(report_data)
    _ensure_functionality_details(report_data)
    _order_functionality_section(report_data)
    report_data["vulnerability_sections"] = [
        s
        for s in report_data.get("vulnerability_sections", [])
        if (s.get("section_name") or "").strip().lower() not in EXCLUDED_VULN_SECTIONS
    ]
    report_data["overall_evaluation"] = _build_overall_evaluation(report_data, section_to_area)
    report_data["risk_summary"] = _build_risk_summary(report_data, section_to_area)
    report_data["findings_severity"] = _build_findings_severity(report_data)

    return _prune_placeholder_rows(report_data)


def _add_permission_display_names(report_data: dict[str, Any]) -> None:
    permissions = report_data.get("permissions")
    if not isinstance(permissions, list):
        return

    for permission in permissions:
        if not isinstance(permission, dict):
            continue
        permission["display_permission"] = _permission_display_name(permission.get("permission"))


def _ensure_functionality_details(report_data: dict[str, Any]) -> None:
    functionality = report_data.get("functionality")
    if not isinstance(functionality, dict):
        return

    for name, details in functionality.items():
        if not isinstance(details, dict):
            continue
        if _non_empty_string(details.get("explanation")):
            continue
        if bool(details.get("present")):
            details["explanation"] = f"{name} functionality was identified in the available scan evidence."
        else:
            details["explanation"] = f"No permission or scan evidence indicated {name} functionality."


def _order_functionality_section(report_data: dict[str, Any]) -> None:
    functionality = report_data.get("functionality")
    if not isinstance(functionality, dict):
        return

    present_items: list[tuple[str, dict[str, Any]]] = []
    absent_items: list[tuple[str, dict[str, Any]]] = []

    for name, details in functionality.items():
        if not isinstance(details, dict):
            continue
        if bool(details.get("present")):
            present_items.append((name, details))
        else:
            absent_items.append((name, details))

    ordered: dict[str, dict[str, Any]] = {}
    for name, details in [*present_items, *absent_items]:
        ordered[name] = details
    report_data["functionality"] = ordered


def _permission_display_name(permission: object) -> str:
    text = str(permission or "").strip()
    android_prefix = "android.permission."
    if text.startswith(android_prefix):
        return text[len(android_prefix) :]
    return text


def _canonicalize_code_section(report_data: dict[str, Any]) -> None:
    sections = report_data.get("vulnerability_sections")
    if not isinstance(sections, list):
        return

    code_section = None
    for section in sections:
        if str(section.get("section_name", "")).strip().lower() == "code":
            code_section = section
            break
    if code_section is None:
        return

    incoming_checks = list(code_section.get("checks") or [])
    lookup = {
        _normalized_check_name(check.get("check")): check
        for check in incoming_checks
        if isinstance(check, dict) and str(check.get("check", "")).strip()
    }
    code_section["checks"] = [_canonical_code_check(report_data, spec, lookup) for spec in CODE_CHECK_SPECS]


def _canonicalize_network_section(report_data: dict[str, Any]) -> None:
    sections = report_data.get("vulnerability_sections")
    if not isinstance(sections, list):
        return

    network_section = None
    for section in sections:
        if str(section.get("section_name", "")).strip().lower() == "network":
            network_section = section
            break
    if network_section is None:
        return

    incoming_checks = list(network_section.get("checks") or [])
    lookup = {
        _normalized_check_name(check.get("check")): check
        for check in incoming_checks
        if isinstance(check, dict) and str(check.get("check", "")).strip()
    }

    canonical_checks = [_canonical_network_check(report_data, spec, lookup) for spec in NETWORK_CHECK_SPECS]
    network_section["checks"] = canonical_checks


def _canonicalize_storage_section(report_data: dict[str, Any]) -> None:
    sections = report_data.get("vulnerability_sections")
    if not isinstance(sections, list):
        return

    storage_section = None
    for section in sections:
        if str(section.get("section_name", "")).strip().lower() == "storage":
            storage_section = section
            break
    if storage_section is None:
        return

    incoming_checks = list(storage_section.get("checks") or [])
    lookup = {
        _normalized_check_name(check.get("check")): check
        for check in incoming_checks
        if isinstance(check, dict) and str(check.get("check", "")).strip()
    }

    storage_section["checks"] = [_canonical_storage_check(report_data, spec, lookup) for spec in STORAGE_CHECK_SPECS]


def _canonicalize_resilience_section(report_data: dict[str, Any]) -> None:
    sections = report_data.get("vulnerability_sections")
    if not isinstance(sections, list):
        return

    resilience_section = None
    for section in sections:
        if str(section.get("section_name", "")).strip().lower() == "resilience":
            resilience_section = section
            break
    if resilience_section is None:
        return

    incoming_checks = list(resilience_section.get("checks") or [])
    lookup = {
        _normalized_check_name(check.get("check")): check
        for check in incoming_checks
        if isinstance(check, dict) and str(check.get("check", "")).strip()
    }

    resilience_section["checks"] = [
        _canonical_resilience_check(report_data, spec, lookup) for spec in RESILIENCE_CHECK_SPECS
    ]


def _canonicalize_ios_code_section(report_data: dict[str, Any]) -> None:
    _canonicalize_ios_section(report_data, "code", IOS_CODE_CHECK_SPECS)


def _canonicalize_ios_network_section(report_data: dict[str, Any]) -> None:
    _canonicalize_ios_section(report_data, "network", IOS_NETWORK_CHECK_SPECS)


def _canonicalize_ios_data_section(report_data: dict[str, Any]) -> None:
    _canonicalize_ios_section(report_data, "data", IOS_DATA_CHECK_SPECS)


def _canonicalize_ios_resilience_section(report_data: dict[str, Any]) -> None:
    _canonicalize_ios_section(report_data, "resilience", IOS_RESILIENCE_CHECK_SPECS)


def _canonicalize_ios_section(
    report_data: dict[str, Any],
    section_name: str,
    specs: tuple[dict[str, Any], ...],
) -> None:
    """Shared iOS canonicalizer for the Code/Network/Data/Resilience sections.

    Mirrors the Android canonicalizers' precedence: (1) an evidence-dict
    entry (`code_evidence` / `network_evidence` / `data_evidence` /
    `resilience_evidence`, keyed via IOS_SECTION_EVIDENCE) with a non-null
    "present" wins first, since that's the structured, machine-generated
    scan output; (2) a check already present in the incoming
    vulnerability_sections data under its canonical name; (3) one of the
    spec's aliases (covering the legacy seed-list category-code names).
    Anything not found defaults to "Not Present" with the spec's default
    explanation.
    """
    sections = report_data.get("vulnerability_sections")
    if not isinstance(sections, list):
        return

    section = None
    for candidate in sections:
        if str(candidate.get("section_name", "")).strip().lower() == section_name:
            section = candidate
            break
    if section is None:
        return

    incoming_checks = list(section.get("checks") or [])
    lookup = {
        _normalized_check_name(check.get("check")): check
        for check in incoming_checks
        if isinstance(check, dict) and str(check.get("check", "")).strip()
    }

    evidence_top_key, evidence_map = IOS_SECTION_EVIDENCE.get(section_name, (None, {}))
    evidence_dict = report_data.get(evidence_top_key) if evidence_top_key else None
    evidence_dict = evidence_dict if isinstance(evidence_dict, dict) else {}

    section["checks"] = [_canonical_ios_check(spec, lookup, evidence_dict, evidence_map) for spec in specs]


def _canonical_ios_check(
    spec: dict[str, Any],
    lookup: dict[str, dict[str, Any]],
    evidence_dict: dict[str, Any],
    evidence_map: dict[str, str],
) -> dict[str, Any]:
    result = "Not Present"
    explanation = spec["not_present_explanation"]
    compliance = spec["compliance"]
    evidence = ""
    remediation_link = ""

    canonical_name = _normalized_check_name(spec["check"])
    evidence_key = evidence_map.get(canonical_name)
    evidence_entry = evidence_dict.get(evidence_key) if evidence_key else None
    evidence_entry = evidence_entry if isinstance(evidence_entry, dict) else None

    source = lookup.get(canonical_name) or _first_matching_alias(spec, lookup)

    if evidence_entry is not None and evidence_entry.get("present") is not None:
        result = "Present" if evidence_entry.get("present") else "Not Present"
        explanation = spec["present_explanation"] if result == "Present" else spec["not_present_explanation"]
        evidence = _non_empty_string(evidence_entry.get("evidence"))
        if source is not None:
            compliance = _non_empty_string(source.get("compliance")) or compliance
            remediation_link = _non_empty_string(source.get("remediation_link"))
    elif source is not None:
        result = _present_not_present(source.get("result")) or result
        explanation = _non_empty_string(source.get("explanation")) or (
            spec["present_explanation"] if result == "Present" else spec["not_present_explanation"]
        )
        compliance = _non_empty_string(source.get("compliance")) or compliance
        evidence = _non_empty_string(source.get("evidence"))
        remediation_link = _non_empty_string(source.get("remediation_link"))

    return {
        "check": spec["check"],
        "result": result,
        "explanation": explanation,
        "compliance": compliance,
        "remediation_link": remediation_link,
        "evidence": evidence,
        "severity": spec["severity"],
        "confidence_caveat": spec.get("confidence_caveat"),
    }


def _canonicalize_ios_binary_protections(report_data: dict[str, Any]) -> None:
    """Build the IPA Binary Code Analysis rows from a plain protection-name ->
    bool evidence dict (`ipa_binary_evidence`), so descriptions/severities stay
    consistent regardless of what the upstream scan JSON provides. Falls back
    to whatever `ipa_binary_protections` rows were already supplied (e.g. a
    hand-authored mockup) for any protection missing from the evidence dict.
    """
    evidence = report_data.get("ipa_binary_evidence")
    evidence = evidence if isinstance(evidence, dict) else {}

    existing_rows = report_data.get("ipa_binary_protections")
    existing_by_name = {
        _normalized_check_name(row.get("protection")): row
        for row in (existing_rows if isinstance(existing_rows, list) else [])
        if isinstance(row, dict)
    }

    rows: list[dict[str, Any]] = []
    for spec in IPA_BINARY_PROTECTION_SPECS:
        key = _normalized_check_name(spec["protection"])
        flag = _coerce_bool(evidence.get(key)) if key in evidence else None
        if flag is None:
            # fall back to snake_case key variants (e.g. "stack_canary")
            snake_key = key.replace(" ", "_")
            flag = _coerce_bool(evidence.get(snake_key)) if snake_key in evidence else None

        if flag is None and key in existing_by_name:
            rows.append(existing_by_name[key])
            continue

        if flag is None:
            continue

        rows.append(
            {
                "protection": spec["protection"],
                "status": "True" if flag else "False",
                "severity": spec["true_severity"] if flag else spec["false_severity"],
                "description": spec["true_description"] if flag else spec["false_description"],
            }
        )

    report_data["ipa_binary_protections"] = rows


def _apply_ios_derived_checks(report_data: dict[str, Any]) -> None:
    """A handful of iOS checks describe the same structural Mach-O facts as
    the IPA Binary Code Analysis protection flags (ARC / PIE / Stack Canary /
    Symbols Stripped). Rather than requiring these to be entered twice,
    derive them straight from `ipa_binary_evidence` so the checks-conducted
    table and the binary-protections table can never disagree."""
    evidence = report_data.get("ipa_binary_evidence")
    evidence = evidence if isinstance(evidence, dict) else {}

    def flag(key: str) -> bool | None:
        value = evidence.get(key)
        if value is None:
            value = evidence.get(key.replace(" ", "_"))
        return _coerce_bool(value)

    derived_by_check_name = {
        "missing arc binary protections": flag("arc"),
        "position-independent code (pic) not enabled": flag("pie"),
        "stack canaries not enabled": flag("stack canary"),
    }
    derived_by_check_name_resilience = {
        "components contain debug symbols": flag("symbols stripped"),
    }
    spec_by_name = {
        _normalized_check_name(spec["check"]): spec for spec in (*IOS_CODE_CHECK_SPECS, *IOS_RESILIENCE_CHECK_SPECS)
    }

    for section in report_data.get("vulnerability_sections") or []:
        section_name = str(section.get("section_name", "")).strip().lower()
        if section_name == "code":
            derived = derived_by_check_name
        elif section_name == "resilience":
            derived = derived_by_check_name_resilience
        else:
            continue

        for check in section.get("checks") or []:
            canonical_name = _normalized_check_name(check.get("check"))
            if canonical_name not in derived:
                continue
            protection_present = derived[canonical_name]
            if protection_present is None:
                continue
            # All four checks are framed negatively (e.g. "Missing ARC...",
            # "...Not Enabled", "...Contain Debug Symbols" where the
            # underlying flag being true -- ARC on, PIE on, canary on,
            # symbols stripped -- is the protected/good state), so the
            # protection being present always maps to "Not Present" here.
            result = "Not Present" if protection_present else "Present"
            check["result"] = result
            spec = spec_by_name.get(canonical_name)
            if spec is not None:
                check["explanation"] = (
                    spec["present_explanation"] if result == "Present" else spec["not_present_explanation"]
                )
            if not _non_empty_string(check.get("evidence")):
                check["evidence"] = "Derived from IPA Binary Code Analysis evidence"


def _normalize_ios_url_schemes(report_data: dict[str, Any]) -> None:
    schemes = report_data.get("url_schemes")
    if not isinstance(schemes, list):
        report_data["url_schemes"] = []
        return

    normalized: list[dict[str, Any]] = []
    for entry in schemes:
        if not isinstance(entry, dict):
            continue
        url_name = _non_empty_string(entry.get("url_name"))
        raw_schemes = entry.get("schemes")
        if isinstance(raw_schemes, str):
            scheme_list = [s.strip() for s in raw_schemes.split(",") if s.strip()]
        elif isinstance(raw_schemes, list):
            scheme_list = [str(s).strip() for s in raw_schemes if str(s).strip()]
        else:
            scheme_list = []
        if not url_name and not scheme_list:
            continue
        normalized.append({"url_name": url_name, "schemes": scheme_list})

    report_data["url_schemes"] = normalized


def _canonical_storage_check(
    report_data: dict[str, Any],
    spec: dict[str, Any],
    lookup: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    result = "Not Present"
    explanation = spec["not_present_explanation"]
    compliance = spec["compliance"]
    evidence = ""
    remediation_link = ""

    canonical_name = _normalized_check_name(spec["check"])
    source = lookup.get(canonical_name)
    storage_evidence = _storage_evidence_entry(report_data, canonical_name)

    if storage_evidence is not None and storage_evidence.get("present") is not None:
        result = "Present" if storage_evidence.get("present") else "Not Present"
        explanation = _storage_explanation(spec, result)
        evidence = _non_empty_string(storage_evidence.get("evidence"))
        if source is not None:
            compliance = _non_empty_string(source.get("compliance")) or compliance
            remediation_link = _non_empty_string(source.get("remediation_link"))
    elif source is not None:
        result = _present_not_present(source.get("result")) or result
        explanation = _non_empty_string(source.get("explanation")) or _storage_explanation(spec, result)
        compliance = _non_empty_string(source.get("compliance")) or compliance
        evidence = _non_empty_string(source.get("evidence"))
        remediation_link = _non_empty_string(source.get("remediation_link"))
    else:
        alias_source = _first_matching_alias(spec, lookup)
        if alias_source is not None:
            result = _present_not_present(alias_source.get("result")) or result
            explanation = _storage_explanation(spec, result)
            compliance = _non_empty_string(alias_source.get("compliance")) or compliance
            evidence = _non_empty_string(alias_source.get("evidence"))
            remediation_link = _non_empty_string(alias_source.get("remediation_link"))

    return {
        "check": spec["check"],
        "result": result,
        "explanation": explanation,
        "compliance": compliance,
        "remediation_link": remediation_link,
        "evidence": evidence,
        "severity": spec["severity"],
    }


def _canonical_code_check(
    report_data: dict[str, Any],
    spec: dict[str, Any],
    lookup: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    result = "Not Present"
    explanation = spec["not_present_explanation"]
    compliance = spec["compliance"]
    evidence = ""
    remediation_link = ""

    canonical_name = _normalized_check_name(spec["check"])
    source = lookup.get(canonical_name)
    code_evidence = _code_evidence_entry(report_data, canonical_name)

    if code_evidence is not None and code_evidence.get("present") is not None:
        result = "Present" if code_evidence.get("present") else "Not Present"
        explanation = _code_explanation(spec, result)
        evidence = _non_empty_string(code_evidence.get("evidence"))
        if source is not None:
            compliance = _non_empty_string(source.get("compliance")) or compliance
            remediation_link = _non_empty_string(source.get("remediation_link"))
    elif source is not None:
        result = _present_not_present(source.get("result")) or result
        explanation = _non_empty_string(source.get("explanation")) or _code_explanation(spec, result)
        compliance = _non_empty_string(source.get("compliance")) or compliance
        evidence = _non_empty_string(source.get("evidence"))
        remediation_link = _non_empty_string(source.get("remediation_link"))
    else:
        alias_source = _first_matching_alias(spec, lookup)
        if alias_source is not None:
            result = _present_not_present(alias_source.get("result")) or result
            explanation = _code_explanation(spec, result)
            compliance = _non_empty_string(alias_source.get("compliance")) or compliance
            evidence = _non_empty_string(alias_source.get("evidence"))
            remediation_link = _non_empty_string(alias_source.get("remediation_link"))

    return {
        "check": spec["check"],
        "result": result,
        "explanation": explanation,
        "compliance": compliance,
        "remediation_link": remediation_link,
        "evidence": evidence,
        "severity": spec["severity"],
    }


def _canonical_network_check(
    report_data: dict[str, Any],
    spec: dict[str, Any],
    lookup: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    result = "Not Present"
    explanation = spec["not_present_explanation"]
    compliance = spec["compliance"]
    evidence = ""
    remediation_link = ""

    canonical_name = _normalized_check_name(spec["check"])
    source = lookup.get(canonical_name)
    network_evidence = _network_evidence_entry(report_data, canonical_name)

    if network_evidence is not None and network_evidence.get("present") is not None:
        result = "Present" if network_evidence.get("present") else "Not Present"
        explanation = _network_explanation(spec, result)
        evidence = _non_empty_string(network_evidence.get("evidence"))
        if source is not None:
            compliance = _non_empty_string(source.get("compliance")) or compliance
            remediation_link = _non_empty_string(source.get("remediation_link"))
    elif source is not None:
        result = _present_not_present(source.get("result")) or result
        explanation = _non_empty_string(source.get("explanation")) or _network_explanation(spec, result)
        compliance = _non_empty_string(source.get("compliance")) or compliance
        evidence = _non_empty_string(source.get("evidence"))
        remediation_link = _non_empty_string(source.get("remediation_link"))
    else:
        alias_source = _first_matching_network_alias(spec, lookup)
        if alias_source is not None:
            result = _present_not_present(alias_source.get("result")) or result
            explanation = _network_explanation(spec, result)
            evidence = _non_empty_string(alias_source.get("evidence"))

    if (
        source is None
        and (network_evidence is None or network_evidence.get("present") is None)
        and canonical_name == "allows cleartext traffic for all domains"
    ):
        cleartext_result, cleartext_evidence = _derive_cleartext_check(report_data, lookup)
        if cleartext_result is not None:
            result = cleartext_result
            explanation = _network_explanation(spec, result)
            if cleartext_evidence:
                evidence = cleartext_evidence

    if (
        source is None
        and (network_evidence is None or network_evidence.get("present") is None)
        and canonical_name == "weak certificate validation enables mitm attacks"
    ):
        mitm_result, mitm_evidence = _derive_mitm_check(lookup)
        if mitm_result is not None:
            result = mitm_result
            explanation = _network_explanation(spec, result)
            if mitm_evidence:
                evidence = mitm_evidence

    return {
        "check": spec["check"],
        "result": result,
        "explanation": explanation,
        "compliance": compliance,
        "remediation_link": remediation_link,
        "evidence": evidence,
        "severity": spec["severity"],
    }


def _canonical_resilience_check(
    report_data: dict[str, Any],
    spec: dict[str, Any],
    lookup: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    result = "Not Present"
    explanation = spec["not_present_explanation"]
    compliance = spec["compliance"]
    evidence = ""
    remediation_link = ""

    canonical_name = _normalized_check_name(spec["check"])
    source = lookup.get(canonical_name)
    resilience_evidence = _resilience_evidence_entry(report_data, canonical_name)

    if resilience_evidence is not None and resilience_evidence.get("present") is not None:
        result = "Present" if resilience_evidence.get("present") else "Not Present"
        explanation = _resilience_explanation(spec, result)
        evidence = _non_empty_string(resilience_evidence.get("evidence"))
        if source is not None:
            compliance = _non_empty_string(source.get("compliance")) or compliance
            remediation_link = _non_empty_string(source.get("remediation_link"))
    elif source is not None:
        result = _present_not_present(source.get("result")) or result
        explanation = _non_empty_string(source.get("explanation")) or _resilience_explanation(spec, result)
        compliance = _non_empty_string(source.get("compliance")) or compliance
        evidence = _non_empty_string(source.get("evidence"))
        remediation_link = _non_empty_string(source.get("remediation_link"))

    return {
        "check": spec["check"],
        "result": result,
        "explanation": explanation,
        "compliance": compliance,
        "remediation_link": remediation_link,
        "evidence": evidence,
        "severity": spec["severity"],
    }


def _apply_derived_vulnerability_checks(report_data: dict[str, Any]) -> None:
    for section in report_data.get("vulnerability_sections") or []:
        for check in section.get("checks") or []:
            _apply_derived_check(report_data, section, check)


def _apply_derived_check(
    report_data: dict[str, Any],
    section: dict[str, Any],
    check: dict[str, Any],
) -> None:
    section_name = str(section.get("section_name", "")).strip().lower()
    if section_name == "code":
        _apply_derived_code_check(report_data, check)
    elif section_name == "storage":
        _apply_derived_storage_check(report_data, check)


def _apply_derived_code_check(report_data: dict[str, Any], check: dict[str, Any]) -> None:
    check_name = _normalized_check_name(check.get("check"))

    component_key = DERIVED_CHECK_ALIAS_TO_COMPONENT_KEY.get(check_name)
    if component_key is not None:
        _apply_exported_component_check(report_data, check, component_key)
        return

    if check_name == "application data can be backed up":
        _apply_boolean_check(
            report_data,
            check,
            paths=[
                ("application", "allow_backup"),
                ("app_info", "allow_backup"),
                ("manifest", "allow_backup"),
            ],
            present_explanation=(
                "The manifest allows application data backup, which can expose "
                "app data through device backup mechanisms."
            ),
            not_present_explanation=("Application data backup is not enabled based on the available report data."),
            evidence_label="allow_backup",
        )
        return

    if check_name == "app is debuggable":
        _apply_boolean_check(
            report_data,
            check,
            paths=[
                ("application", "debuggable"),
                ("app_info", "debuggable"),
                ("manifest", "debuggable"),
            ],
            present_explanation=(
                "The app is marked as debuggable, which can expose runtime state and make reverse engineering easier."
            ),
            not_present_explanation=("The app is not marked as debuggable based on the available report data."),
            evidence_label="debuggable",
        )
        return

    if check_name == "application uses custom url schemes / deep links":
        _apply_deep_link_check(report_data, check)


def _apply_derived_storage_check(report_data: dict[str, Any], check: dict[str, Any]) -> None:
    check_name = _normalized_check_name(check.get("check"))
    if check_name == "sensitive values stored insecurely in sharedpreferences":
        _apply_location_based_secret_check(
            report_data,
            check,
            hints=SHARED_PREFS_HINTS,
            present_explanation=(
                "Secret-like values were found in SharedPreferences-related paths, "
                "indicating sensitive data may be stored insecurely in local preferences."
            ),
            not_present_explanation=("No secret-like values were found in SharedPreferences-related paths."),
            evidence_label="shared_prefs_secret_hits",
        )
        return

    if check_name == "sensitive data in http cache databases":
        _apply_location_based_secret_check(
            report_data,
            check,
            hints=CACHE_HINTS,
            present_explanation=(
                "Secret-like values were found in cache-related paths, indicating "
                "sensitive data may be present in application cache storage."
            ),
            not_present_explanation=("No secret-like values were found in cache-related paths."),
            evidence_label="cache_secret_hits",
        )


def _apply_exported_component_check(
    report_data: dict[str, Any],
    check: dict[str, Any],
    component_key: str,
) -> None:
    app_components = report_data.get("app_components") or {}
    if component_key not in app_components:
        return

    exported_count = _coerce_int(app_components.get(component_key))
    if exported_count is None:
        return

    component_label = component_key.removeprefix("exported_").replace("_", " ")
    singular = component_label[:-1] if component_label.endswith("s") else component_label
    plural = component_label if component_label.endswith("s") else f"{component_label}s"

    if exported_count > 0:
        check["result"] = "Present"
        noun = singular if exported_count == 1 else plural
        check["explanation"] = f"{exported_count} exported {noun} detected in the manifest."
        check["evidence"] = f"{component_key}={exported_count}"
        return

    check["result"] = "Not Present"
    check["explanation"] = f"No exported {plural} were detected in the manifest."
    check["evidence"] = f"{component_key}=0"


def _apply_boolean_check(
    report_data: dict[str, Any],
    check: dict[str, Any],
    *,
    paths: list[tuple[str, str]],
    present_explanation: str,
    not_present_explanation: str,
    evidence_label: str,
) -> None:
    for section_key, field_key in paths:
        section = report_data.get(section_key)
        if not isinstance(section, dict) or field_key not in section:
            continue
        flag = _coerce_bool(section.get(field_key))
        if flag is None:
            continue
        check["result"] = "Present" if flag else "Not Present"
        check["explanation"] = present_explanation if flag else not_present_explanation
        check["evidence"] = f"{evidence_label}={str(flag).lower()}"
        return


def _apply_deep_link_check(report_data: dict[str, Any], check: dict[str, Any]) -> None:
    deep_links = report_data.get("deep_links")
    if not isinstance(deep_links, dict):
        return

    entries = deep_links.get("deep_links")
    if not isinstance(entries, list):
        return

    count = len(entries)
    if count > 0:
        check["result"] = "Present"
        noun = "handler" if count == 1 else "handlers"
        check["explanation"] = f"{count} custom URL scheme or deep link {noun} detected in the app."
        check["evidence"] = f"deep_links={count}"
        return

    check["result"] = "Not Present"
    check["explanation"] = "No custom URL schemes or deep links were detected."
    check["evidence"] = "deep_links=0"


def _apply_location_based_secret_check(
    report_data: dict[str, Any],
    check: dict[str, Any],
    *,
    hints: tuple[str, ...],
    present_explanation: str,
    not_present_explanation: str,
    evidence_label: str,
) -> None:
    secrets = _secret_entries(report_data)
    matched = [secret for secret in secrets if any(hint in str(secret.get("location", "")).lower() for hint in hints)]
    if matched:
        check["result"] = "Present"
        check["explanation"] = present_explanation
        check["evidence"] = f"{evidence_label}={len(matched)}"
        return

    if secrets:
        check["result"] = "Not Present"
        check["explanation"] = not_present_explanation
        check["evidence"] = f"{evidence_label}=0"


def _secret_entries(report_data: dict[str, Any]) -> list[dict[str, Any]]:
    hardcoded_values = report_data.get("hardcoded_values")
    if not isinstance(hardcoded_values, dict):
        return []
    secrets = hardcoded_values.get("secrets")
    if not isinstance(secrets, list):
        return []
    return [secret for secret in secrets if isinstance(secret, dict)]


def _network_evidence_entry(report_data: dict[str, Any], canonical_check_name: str) -> dict[str, Any] | None:
    network_evidence = report_data.get("network_evidence")
    if not isinstance(network_evidence, dict):
        return None
    evidence_key = NETWORK_EVIDENCE_KEY_BY_CHECK.get(canonical_check_name)
    if not evidence_key:
        return None
    entry = network_evidence.get(evidence_key)
    if not isinstance(entry, dict):
        return None
    return entry


def _storage_evidence_entry(report_data: dict[str, Any], canonical_check_name: str) -> dict[str, Any] | None:
    storage_evidence = report_data.get("storage_evidence")
    if not isinstance(storage_evidence, dict):
        return None
    evidence_key = STORAGE_EVIDENCE_KEY_BY_CHECK.get(canonical_check_name)
    if not evidence_key:
        return None
    entry = storage_evidence.get(evidence_key)
    if not isinstance(entry, dict):
        return None
    return entry


def _resilience_evidence_entry(report_data: dict[str, Any], canonical_check_name: str) -> dict[str, Any] | None:
    resilience_evidence = report_data.get("resilience_evidence")
    if not isinstance(resilience_evidence, dict):
        return None
    evidence_key = RESILIENCE_EVIDENCE_KEY_BY_CHECK.get(canonical_check_name)
    if not evidence_key:
        return None
    entry = resilience_evidence.get(evidence_key)
    if not isinstance(entry, dict):
        return None
    return entry


def _code_evidence_entry(report_data: dict[str, Any], canonical_check_name: str) -> dict[str, Any] | None:
    code_evidence = report_data.get("code_evidence")
    if not isinstance(code_evidence, dict):
        return None
    evidence_key = CODE_EVIDENCE_KEY_BY_CHECK.get(canonical_check_name)
    if not evidence_key:
        return None
    entry = code_evidence.get(evidence_key)
    if not isinstance(entry, dict):
        return None
    return entry


def _first_matching_network_alias(
    spec: dict[str, Any],
    lookup: dict[str, dict[str, Any]],
) -> dict[str, Any] | None:
    return _first_matching_alias(spec, lookup)


def _first_matching_alias(
    spec: dict[str, Any],
    lookup: dict[str, dict[str, Any]],
) -> dict[str, Any] | None:
    for alias in spec.get("aliases", ()):
        source = lookup.get(alias)
        if source is not None:
            return source
    return None


def _derive_cleartext_check(
    report_data: dict[str, Any],
    lookup: dict[str, dict[str, Any]],
) -> tuple[str | None, str]:
    evidence: list[str] = []
    for alias in (
        "network security configuration allows cleartext traffic",
        "network security config allows cleartext traffic for all domains",
        "clear text traffic is enabled for app",
    ):
        source = lookup.get(alias)
        if source is None:
            continue
        if _present_not_present(source.get("result")) == "Present":
            if _non_empty_string(source.get("evidence")):
                evidence.append(_non_empty_string(source.get("evidence")))
            return "Present", ", ".join(_dedupe_preserve_order(evidence))

    for section_key, field_key, label in (
        ("application", "uses_cleartext_traffic", "uses_cleartext_traffic=true"),
        ("manifest", "uses_cleartext_traffic", "uses_cleartext_traffic=true"),
        ("network_security", "allows_cleartext_traffic", "network_security_allows_cleartext=true"),
    ):
        section = report_data.get(section_key)
        if not isinstance(section, dict):
            continue
        flag = _coerce_bool(section.get(field_key))
        if flag is True:
            return "Present", label

    return None, ""


def _derive_mitm_check(
    lookup: dict[str, dict[str, Any]],
) -> tuple[str | None, str]:
    evidence: list[str] = []
    for name in (
        "weak certificate validation enables mitm attacks",
        "contains hostnameverifier that accepts all hostnames",
        "contains x509trustmanager that accepts all certificates",
        "network security configuration allows user-installed cas",
    ):
        source = lookup.get(name)
        if source is None:
            continue
        if _present_not_present(source.get("result")) == "Present":
            if _non_empty_string(source.get("evidence")):
                evidence.append(_non_empty_string(source.get("evidence")))
            return "Present", ", ".join(_dedupe_preserve_order(evidence))
    return None, ""


def _network_explanation(spec: dict[str, Any], result: str) -> str:
    if _normalized_check_name(result) == "present":
        return spec["present_explanation"]
    return spec["not_present_explanation"]


def _storage_explanation(spec: dict[str, Any], result: str) -> str:
    if _normalized_check_name(result) == "present":
        return spec["present_explanation"]
    return spec["not_present_explanation"]


def _resilience_explanation(spec: dict[str, Any], result: str) -> str:
    if _normalized_check_name(result) == "present":
        return spec["present_explanation"]
    return spec["not_present_explanation"]


def _code_explanation(spec: dict[str, Any], result: str) -> str:
    if _normalized_check_name(result) == "present":
        return spec["present_explanation"]
    return spec["not_present_explanation"]


def _blank_template() -> dict[str, Any]:
    return json.loads(BLANK_TEMPLATE_PATH.read_text(encoding="utf-8"))


def _ios_blank_template() -> dict[str, Any]:
    return json.loads(IOS_BLANK_TEMPLATE_PATH.read_text(encoding="utf-8"))


def _merge_nested(base: Any, override: Any) -> Any:
    if isinstance(base, dict) and isinstance(override, dict):
        merged = {key: copy.deepcopy(value) for key, value in base.items()}
        for key, value in override.items():
            if key in merged:
                merged[key] = _merge_nested(merged[key], value)
            else:
                merged[key] = copy.deepcopy(value)
        return merged

    if isinstance(base, list) and isinstance(override, list):
        if override:
            return copy.deepcopy(override)
        return copy.deepcopy(base)

    return copy.deepcopy(override)


def _build_findings_severity(report_data: dict[str, Any]) -> dict[str, int]:
    counts = {key: 0 for key in FINDINGS_SEVERITY_KEYS}

    for section in report_data.get("vulnerability_sections") or []:
        for check in section.get("checks") or []:
            severity = str(check.get("severity", "")).strip().lower()
            if severity in counts:
                counts[severity] += 1

    return counts


def _build_overall_evaluation(
    report_data: dict[str, Any],
    section_to_area: dict[str, tuple[str, str]] = SECTION_TO_AREA,
) -> list[dict[str, Any]]:
    rows_by_area: dict[str, dict[str, Any]] = {}

    for section in report_data.get("vulnerability_sections") or []:
        section_name = str(section.get("section_name", "")).strip().lower()
        area_details = section_to_area.get(section_name)
        if area_details is None:
            continue

        area_label, _risk_key = area_details
        present_checks = [
            check
            for check in (section.get("checks") or [])
            if str(check.get("result", "")).strip().lower() == "present"
        ]
        summary_checks = [
            check
            for check in present_checks
            if str(check.get("severity", "")).strip().lower() in SECTION_SEVERITY_ORDER
        ]
        risk_rating = _highest_present_severity(summary_checks) if summary_checks else "Low"
        highest_severity = risk_rating.lower()
        summary_findings = [
            str(check.get("check", "")).strip()
            for check in summary_checks
            if str(check.get("severity", "")).strip().lower() == highest_severity
            and str(check.get("check", "")).strip()
        ]

        rows_by_area[area_label] = {
            "area_of_concern": area_label,
            "risk_rating": risk_rating,
            "summary_findings": summary_findings or ["No findings identified in this scan"],
        }

    ordered_rows: list[dict[str, Any]] = []
    for area_label, _risk_key in section_to_area.values():
        row = rows_by_area.get(area_label)
        if row is not None:
            ordered_rows.append(row)

    return ordered_rows


def _build_risk_summary(
    report_data: dict[str, Any],
    section_to_area: dict[str, tuple[str, str]] = SECTION_TO_AREA,
) -> dict[str, str]:
    summary = {risk_key: "Low" for _area_label, risk_key in section_to_area.values()}

    for row in report_data.get("overall_evaluation") or []:
        area_name = str(row.get("area_of_concern", "")).strip().lower()
        for section_name, (area_label, risk_key) in section_to_area.items():
            if area_label.lower() == area_name:
                summary[risk_key] = _normalize_risk_level(row.get("risk_rating"))
                break

    return summary


def _highest_present_severity(present_checks: list[dict[str, Any]]) -> str:
    highest = "info"
    highest_rank = SECTION_SEVERITY_ORDER[highest]

    for check in present_checks:
        severity = str(check.get("severity", "")).strip().lower()
        if severity not in SECTION_SEVERITY_ORDER:
            continue
        rank = SECTION_SEVERITY_ORDER[severity]
        if rank > highest_rank:
            highest = severity
            highest_rank = rank

    return highest.title()


def _normalize_risk_level(value: object) -> str:
    text = str(value or "").strip().lower()
    if text in {"critical", "high"}:
        return "High"
    if text == "medium":
        return "Medium"
    return "Low"


def _normalized_check_name(value: object) -> str:
    return str(value or "").strip().lower()


def _non_empty_string(value: object) -> str:
    text = str(value or "").strip()
    return text


def _present_not_present(value: object) -> str:
    text = str(value or "").strip().lower()
    if text == "present":
        return "Present"
    if text == "not present":
        return "Not Present"
    return ""


def _dedupe_preserve_order(values: list[str]) -> list[str]:
    seen: set[str] = set()
    deduped: list[str] = []
    for value in values:
        if value in seen or not value:
            continue
        seen.add(value)
        deduped.append(value)
    return deduped


def _coerce_int(value: object) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _coerce_bool(value: object) -> bool | None:
    if isinstance(value, bool):
        return value
    text = str(value or "").strip().lower()
    if text in {"true", "1", "yes"}:
        return True
    if text in {"false", "0", "no"}:
        return False
    return None


def _prune_placeholder_rows(data: dict[str, Any]) -> dict[str, Any]:
    if not any(data.get("permissions") or []):
        data["permissions"] = []
    elif len(data["permissions"]) == 1 and not any(str(value).strip() for value in data["permissions"][0].values()):
        data["permissions"] = []

    hardcoded_values = data.get("hardcoded_values") or {}
    urls = hardcoded_values.get("urls") or []
    if len(urls) == 1 and not any(str(value).strip() for value in urls[0].values()):
        hardcoded_values["urls"] = []

    endpoints = data.get("endpoints") or []
    if len(endpoints) == 1 and not any(str(value).strip() for value in endpoints[0].values()):
        data["endpoints"] = []

    return data


def main():
    if len(sys.argv) not in (3, 4):
        print("Usage: python3 generate_report.py <data.json> <output.pdf> [--show-confidence-caveats]")
        sys.exit(1)

    data_path = Path(sys.argv[1])
    output_path = Path(sys.argv[2])
    show_confidence_caveats = len(sys.argv) == 4 and sys.argv[3] == "--show-confidence-caveats"
    generate_report(data_path, output_path, show_confidence_caveats=show_confidence_caveats)


if __name__ == "__main__":
    main()
