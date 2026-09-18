"""Canonical native Android source checks and their evidence bindings."""

from dataclasses import replace

from adapters.output.phoenix_report.builders.source import SourceCheckDefinition
from domain.report import CheckSeverity, ReportPlatform

_ANDROID_SOURCE_SECTION_CHECKS = (
    (
        "Code",
        "code_evidence",
        (
            SourceCheckDefinition(
                name="Activities Accessible to Other Apps",
                evidence_key="activities_accessible_to_other_apps",
                severity=CheckSeverity.HIGH,
                compliance="OWASP: 2016-M1-Improper Platform Usage",
                present_explanation="One or more activities are exported or otherwise accessible to other apps.",
                not_present_explanation="No activities are exported, or access to all activities is restricted by use of permissions.",
            ),
            SourceCheckDefinition(
                name="App is Debuggable",
                evidence_key="app_is_debuggable",
                severity=CheckSeverity.HIGH,
                compliance="OWASP: 2016-M10-Extraneous Functionality",
                present_explanation="The app is debuggable. A malicious actor with physical access to a device that has USB debugging enabled can attach a debugger to the app's process during execution. This is dangerous because it could expose sensitive information, enable reverse engineering, and allow the execution of arbitrary code.",
                not_present_explanation="The app is not marked as debuggable based on the available manifest evidence.",
            ),
            SourceCheckDefinition(
                name="Application Data can be Backed Up",
                evidence_key="application_data_can_be_backed_up",
                severity=CheckSeverity.MEDIUM,
                compliance="OWASP: 2016-M2-Insecure Data Storage",
                present_explanation="The manifest allows application data backup.",
                not_present_explanation="The manifest does not enable application data backup.",
            ),
            SourceCheckDefinition(
                name="Application Uses Custom URL Schemes / Deep Links",
                evidence_key="application_uses_custom_url_schemes_or_deep_links",
                severity=CheckSeverity.MEDIUM,
                compliance="OWASP: 2016-M1-Improper Platform Usage",
                present_explanation="The manifest declares one or more custom URL schemes or deep links.",
                not_present_explanation="No custom URL schemes or deep links were declared.",
            ),
            SourceCheckDefinition(
                name="Contains Hard-coded Cryptographic Key",
                evidence_key="contains_hard_coded_cryptographic_key",
                severity=CheckSeverity.HIGH,
                compliance="OWASP: 2016-M5-Insufficient Cryptography; 2016-M9-Reverse Engineering",
                present_explanation="Potential hard-coded cryptographic key material was found in the app.",
                not_present_explanation="No hard-coded cryptographic keys were found in the app.",
            ),
            SourceCheckDefinition(
                name="Contains Potential Hard-coded Password",
                evidence_key="contains_potential_hard_coded_password",
                severity=CheckSeverity.HIGH,
                compliance="OWASP: 2016-M9-Reverse Engineering",
                present_explanation="Potential hard-coded password material was found in the app.",
                not_present_explanation="No hard-coded passwords were found in the app.",
            ),
            SourceCheckDefinition(
                name="Contains Potential SQL Injection",
                evidence_key="contains_potential_sql_injection",
                severity=CheckSeverity.HIGH,
                compliance="OWASP: 2016-M7-Client Code Quality; NIAP: FPT_API_EXT.2.1",
                present_explanation="Potential SQL injection behavior was found in the app.",
                not_present_explanation="No potential SQL injection vulnerabilities were found.",
            ),
            SourceCheckDefinition(
                name="Contains Reflection Code",
                evidence_key="contains_reflection_code",
                severity=CheckSeverity.MEDIUM,
                present_explanation="The app contains Java reflection code.",
                not_present_explanation="The app does not contain Java reflection code.",
            ),
            SourceCheckDefinition(
                name="Creates Blowfish Key with Weak Length",
                evidence_key="creates_blowfish_key_with_weak_length",
                severity=CheckSeverity.HIGH,
                compliance="OWASP: 2016-M5-Insufficient Cryptography; NIAP: FCS_COP.1.1(1)",
                present_explanation="The app creates a Blowfish key with less than 128 bits in length.",
                not_present_explanation="The app does not create a Blowfish key with less than 128 bits in length.",
            ),
            SourceCheckDefinition(
                name="Creates RSA Keys with Weak Modulus Length",
                evidence_key="creates_rsa_keys_with_weak_modulus_length",
                severity=CheckSeverity.HIGH,
                compliance="OWASP: 2016-M5-Insufficient Cryptography; NIAP: FCS_CKM.1.1(1)",
                present_explanation="The app creates an RSA key with modulus length less than 1024 bits.",
                not_present_explanation="The app does not create an RSA key with modulus length less than 1024 bits.",
            ),
            SourceCheckDefinition(
                name="Receivers Accessible to Other Apps",
                evidence_key="receivers_accessible_to_other_apps",
                severity=CheckSeverity.HIGH,
                compliance="OWASP: 2016-M1-Improper Platform Usage; NIAP: FMT_CFG_EXT.1.2",
                present_explanation="One or more receivers are exported or otherwise accessible to other apps.",
                not_present_explanation="The app does not contain receivers, no receivers are exported, or access to all exported receivers is restricted by use of permissions.",
            ),
            SourceCheckDefinition(
                name="Requests Root Access",
                evidence_key="requests_root_access",
                severity=CheckSeverity.HIGH,
                compliance="OWASP: 2016-M8-Code Tampering",
                present_explanation="The app requests root access or superuser privileges. This allows the app to execute more advanced or potentially dangerous operations on the device.",
                not_present_explanation="No root-access or superuser execution requests were identified.",
            ),
            SourceCheckDefinition(
                name="Services Accessible to Other Apps",
                evidence_key="services_accessible_to_other_apps",
                severity=CheckSeverity.HIGH,
                compliance="OWASP: 2016-M1-Improper Platform Usage; NIAP: FMT_CFG_EXT.1.2",
                present_explanation="One or more services are exported or otherwise accessible to other apps.",
                not_present_explanation="The app does not contain services, no services are exported, or access to all services is restricted by use of permissions.",
            ),
            SourceCheckDefinition(
                name="Uses SHA1 Hashing Algorithm",
                evidence_key="uses_sha1_hashing_algorithm",
                severity=CheckSeverity.HIGH,
                compliance="OWASP: 2016-M5-Insufficient Cryptography; NIAP: FCS_TUD_EXT.1.6",
                present_explanation="The app uses the SHA1 hashing algorithm, which is vulnerable to collision attacks.",
                not_present_explanation="No SHA1 hashing usage was identified in the available code-analysis evidence.",
            ),
            SourceCheckDefinition(
                name="Weakly Configured XML Parser",
                evidence_key="weakly_configured_xml_parser",
                severity=CheckSeverity.MEDIUM,
                compliance="OWASP: 2016-M7-Client Code Quality; NIAP: FPT_API_EXT.2.1",
                present_explanation="Potential weakly configured XML parsing behavior was found.",
                not_present_explanation="No potential weakly configured XML parsing is found.",
            ),
            SourceCheckDefinition(
                name="Writes Sensitive Information to System Log",
                evidence_key="writes_sensitive_information_to_system_log",
                severity=CheckSeverity.MEDIUM,
                compliance="OWASP: 2016-M2-Insecure Data Storage; NIAP: FDP_DEC_EXT.1.2; HIPAA: 164.312(a)(2)(iv); GDPR: Articles 5, Article 25, Article 32",
                present_explanation="The app may write sensitive information to the system log.",
                not_present_explanation="This app was not observed to write sensitive information to the system log.",
            ),
            SourceCheckDefinition(
                name="Uses Spoofable Values for Authentication",
                evidence_key="uses_spoofable_values_for_authentication",
                severity=CheckSeverity.HIGH,
                compliance="OWASP: 2016-M4-Insecure Authentication",
                present_explanation="The app authenticates using values that may be spoofed.",
                not_present_explanation="This app does not authenticate using values that can be spoofed.",
            ),
            SourceCheckDefinition(
                name="Copies Sensitive Information into the Clipboard Without User Consent",
                evidence_key="copies_sensitive_information_into_clipboard_without_user_consent",
                severity=CheckSeverity.MEDIUM,
                compliance="OWASP: 2016-M2-Insecure Data Storage; HIPAA: 164.312(a)(2)(iv)",
                present_explanation="The app copies sensitive information into the clipboard without the user's consent.",
                not_present_explanation="This app does not copy sensitive information into the clipboard without the user's consent.",
            ),
        ),
    ),
    (
        "Network",
        "network_evidence",
        (
            SourceCheckDefinition(
                name="Allows Cleartext Traffic for All Domains",
                evidence_key="allows_cleartext_traffic_for_all_domains",
                severity=CheckSeverity.HIGH,
                compliance="OWASP: 2016-M3-Insecure Communication; NIAP: FTP_DIT_EXT.1.1; HIPAA: 164.312(e)(2)(ii); GDPR: Articles 5, Article 25, Article 32",
                present_explanation="The app allows cleartext traffic for all domains by omitting a network security configuration file or explicitly allowing all cleartext traffic.",
                not_present_explanation="The app does not appear to allow cleartext traffic for all domains based on the available network configuration evidence.",
            ),
            SourceCheckDefinition(
                name="Contains HostnameVerifier That Accepts All Hostnames",
                evidence_key="contains_hostname_verifier_accepts_all",
                severity=CheckSeverity.HIGH,
                compliance="OWASP: 2016-M3-Insecure Communication; NIAP: FIA_X509_EXT.1.1",
                present_explanation="A weak HostnameVerifier was found that accepts all hostnames, which can allow the app to trust unexpected TLS endpoints.",
                not_present_explanation="No weak HostnameVerifiers are found.",
            ),
            SourceCheckDefinition(
                name="Contains X509TrustManager that Accepts All Certificates",
                evidence_key="contains_x509_trust_manager_accepts_all",
                severity=CheckSeverity.HIGH,
                compliance="OWASP: 2016-M3-Insecure Communication; NIAP: FIA_X509_EXT.1.1",
                present_explanation="A weak X509TrustManager was found that accepts all certificates, which can allow interception of TLS traffic.",
                not_present_explanation="No weak X509TrustManagers are found.",
            ),
            SourceCheckDefinition(
                name="Opens a Listening Port",
                evidence_key="opens_listening_port",
                severity=CheckSeverity.MEDIUM,
                compliance="NIAP: FDP_NET_EXT.1.1",
                present_explanation="The app opens a listening port on the device, which can increase the attack surface for local network or inter-app attacks.",
                not_present_explanation="This app does not open a listening port on the device.",
            ),
            SourceCheckDefinition(
                name="Sensitive Information is Unencrypted in Transit",
                evidence_key="sensitive_information_unencrypted_in_transit",
                severity=CheckSeverity.HIGH,
                compliance="OWASP: 2016-M3-Insecure Communication; NIAP: FTP_DIT_EXT.1.1; HIPAA: 164.312(e)(2)(ii); GDPR: Articles 5, Article 25, Article 32",
                present_explanation="This app sends sensitive information over the network without encryption. An adversary on the local network or on-path could easily capture this sensitive information.",
                not_present_explanation="No unencrypted transmission of sensitive information was identified in this scan.",
            ),
            SourceCheckDefinition(
                name="Weak Certificate Validation Enables MitM Attacks",
                evidence_key="weak_certificate_validation_enables_mitm",
                severity=CheckSeverity.HIGH,
                compliance="OWASP: 2016-M3-Insecure Communication; NIAP: FIA_X509_EXT.1.1; HIPAA: 164.312(e)(2)(ii); GDPR: Articles 5, Article 25, Article 32",
                present_explanation="The app is vulnerable to man-in-the-middle attacks due to flawed certificate validation.",
                not_present_explanation="No weak certificate-validation behavior leading to man-in-the-middle exposure was identified in this scan.",
            ),
        ),
    ),
    (
        "Data Storage",
        "data_storage_evidence",
        (
            SourceCheckDefinition(
                name="Accesses External Storage",
                evidence_key="accesses_external_storage",
                severity=CheckSeverity.MEDIUM,
                compliance="OWASP: 2016-M2-Insecure Data Storage; NIAP: FDP_DAR_EXT.1.1; HIPAA: 164.312(a)(2)(iv); GDPR: Articles 5, 25, 32",
                present_explanation="The app accesses the external storage directory, which can be accessed by other apps with the required permission.",
                not_present_explanation="No evidence was found that the app accesses shared external storage.",
            ),
            SourceCheckDefinition(
                name="Sensitive Information Stored in World Readable or Writable File in Internal Storage",
                evidence_key="sensitive_information_stored_in_world_readable_or_writable_file_in_internal_storage",
                severity=CheckSeverity.HIGH,
                compliance="OWASP: 2016-M2-Insecure Data Storage; NIAP: FDP_DAR_EXT.1.1; FMT_CFG_EXT.1.2; FMT_MEC_EXT.1.1; HIPAA: 164.312(a)(2)(iv); GDPR: Articles 5, 25, 32",
                present_explanation="The app stores sensitive information in internal storage using world-readable or world-writable file modes.",
                not_present_explanation="This app does not create world readable or writable files with sensitive information in its internal storage.",
            ),
            SourceCheckDefinition(
                name="Sensitive Information Stored in External Storage",
                evidence_key="sensitive_information_stored_in_external_storage",
                severity=CheckSeverity.HIGH,
                compliance="OWASP: 2016-M2-Insecure Data Storage; NIAP: FDP_DAR_EXT.1.1; FMT_CFG_EXT.1.2; FMT_MEC_EXT.1.1; HIPAA: 164.312(a)(2)(iv); GDPR: Articles 5, 25, 32",
                present_explanation="The app stores sensitive information on the device in external storage, accessible from other apps with the required permission.",
                not_present_explanation="No evidence was found that the app stores sensitive information in external storage.",
            ),
        ),
    ),
    (
        "Resilience",
        "resilience_evidence",
        (
            SourceCheckDefinition(
                name="Biometric / Local Authentication Bypass Possible",
                evidence_key="biometric_local_authentication_bypass_possible",
                severity=CheckSeverity.MEDIUM,
                present_explanation="Biometric or local authentication use was identified without strong evidence of crypto-backed binding or equivalent hardening.",
                not_present_explanation="No biometric/local authentication flow was identified, or available evidence suggests crypto-backed hardening is present.",
            ),
        ),
    ),
)


ANDROID_SOURCE_SECTION_CHECKS = tuple(
    (
        section,
        evidence_key,
        tuple(
            replace(definition, applicable_platforms=frozenset({ReportPlatform.ANDROID})) for definition in definitions
        ),
    )
    for section, evidence_key, definitions in _ANDROID_SOURCE_SECTION_CHECKS
)
