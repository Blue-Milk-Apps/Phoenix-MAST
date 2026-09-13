"""Canonical iOS binary security checks."""

from dataclasses import dataclass

from domain.report import CheckSeverity


def normalize_check_name(name: str) -> str:
    return " ".join(name.lower().split())


@dataclass(frozen=True)
class IOSBinaryCheckDefinition:
    name: str
    severity: CheckSeverity
    evidence_key: str
    compliance: str = ""
    present_explanation: str = ""
    not_present_explanation: str = ""
    aliases: tuple[str, ...] = ()

    @property
    def normalized_name(self) -> str:
        return normalize_check_name(self.name)


CODE_CHECKS = tuple(
    IOSBinaryCheckDefinition(
        name, severity, key, compliance, f"{name} was identified.", f"{name} was not identified.", aliases
    )
    for name, severity, key, compliance, aliases in (
        ("Deprecated API - UIWebView", CheckSeverity.MEDIUM, "uses_uiwebview", "MASVS-PLATFORM-2", ()),
        ("Insecure Nanopb Library", CheckSeverity.HIGH, "insecure_nanopb_library", "MASVS-CODE-3", ()),
        (
            "Insecure Serialization API - NSKeyedUnarchiver",
            CheckSeverity.HIGH,
            "insecure_nskeyedunarchiver_usage",
            "MASVS-CODE-4",
            (),
        ),
        (
            "Missing ARC Binary Protections",
            CheckSeverity.MEDIUM,
            "missing_arc",
            "MASVS-CODE-4",
            ("arc binary protections",),
        ),
        (
            "Position-Independent Code (PIC) Not Enabled",
            CheckSeverity.MEDIUM,
            "pic_not_enabled",
            "MASVS-CODE-4",
            ("pic binary protections",),
        ),
        (
            "Stack Canaries Not Enabled",
            CheckSeverity.MEDIUM,
            "stack_canaries_not_enabled",
            "MASVS-CODE-4",
            ("stack smashing protections",),
        ),
        ("Insecure API Usage in Binary", CheckSeverity.MEDIUM, "insecure_api_usage_in_binary", "MASVS-CODE-4", ()),
        (
            "Usage of malloc Instead of calloc in Binary",
            CheckSeverity.MEDIUM,
            "malloc_instead_of_calloc",
            "MASVS-CODE-4",
            (),
        ),
        (
            "Application Encodes Data Using Insecure Cryptography",
            CheckSeverity.HIGH,
            "encodes_data_using_insecure_cryptography",
            "MASVS-CRYPTO-1",
            (),
        ),
        (
            "Application Utilizes Insecure Cryptography",
            CheckSeverity.HIGH,
            "utilizes_insecure_cryptography",
            "MASVS-CRYPTO-1",
            (),
        ),
        ("PBKDF2 Iteration Count <10k", CheckSeverity.MEDIUM, "pbkdf2_iteration_count_below_10k", "MASVS-CRYPTO-1", ()),
        (
            "Hardcoded API Keys within the Application Bundle",
            CheckSeverity.HIGH,
            "hardcoded_api_keys_in_bundle",
            "MASVS-CRYPTO-2",
            (),
        ),
        (
            "Potentially Insecure iOS Entitlements",
            CheckSeverity.MEDIUM,
            "insecure_entitlements",
            "MASVS-PLATFORM-1",
            (),
        ),
    )
)
CODE_CHECK_BY_NAME = {c.normalized_name: c for c in CODE_CHECKS}
CODE_CHECK_BY_ALIAS = {normalize_check_name(a): c for c in CODE_CHECKS for a in c.aliases}


def code_check_for_name(name: str):
    return CODE_CHECK_BY_NAME.get(normalize_check_name(name)) or CODE_CHECK_BY_ALIAS.get(normalize_check_name(name))


def code_evidence_key_by_check() -> dict[str, str]:
    return {c.normalized_name: c.evidence_key for c in CODE_CHECKS}


NETWORK_CHECKS = (
    IOSBinaryCheckDefinition(
        "App Transport Security (ATS) Disabled", CheckSeverity.HIGH, "ats_disabled", "MASVS-NETWORK-1"
    ),
    IOSBinaryCheckDefinition(
        "Change Cipher Spec Injection Vulnerable OpenSSL Version",
        CheckSeverity.HIGH,
        "vulnerable_openssl_ccs_injection",
        "MASVS-NETWORK-1",
    ),
    IOSBinaryCheckDefinition(
        "Application Contains Deprecated FTP Functionality", CheckSeverity.MEDIUM, "uses_ftp", "MASVS-NETWORK-1"
    ),
    IOSBinaryCheckDefinition(
        "Application Contains Heartbleed Vulnerable OpenSSL Version",
        CheckSeverity.HIGH,
        "vulnerable_openssl_heartbleed",
        "MASVS-NETWORK-1",
    ),
    IOSBinaryCheckDefinition(
        "Application Contains Insecure HTTP Traffic", CheckSeverity.HIGH, "insecure_http_traffic", "MASVS-NETWORK-1"
    ),
    IOSBinaryCheckDefinition(
        "Application Selectively Disabled ATS Protections",
        CheckSeverity.MEDIUM,
        "ats_exceptions_configured",
        "MASVS-NETWORK-1",
    ),
    IOSBinaryCheckDefinition(
        "Cookie Missing 'HttpOnly' Flag", CheckSeverity.MEDIUM, "cookie_missing_httponly", "MASVS-NETWORK-1"
    ),
    IOSBinaryCheckDefinition(
        "Cookie Missing 'Secure' Flag", CheckSeverity.MEDIUM, "cookie_missing_secure_flag", "MASVS-NETWORK-1"
    ),
    IOSBinaryCheckDefinition(
        "Insecure TLS Configuration", CheckSeverity.HIGH, "insecure_tls_configuration", "MASVS-NETWORK-1"
    ),
    IOSBinaryCheckDefinition(
        "Certificate Pinning Not Implemented",
        CheckSeverity.MEDIUM,
        "certificate_pinning_not_implemented",
        "MASVS-NETWORK-2",
    ),
)
DATA_STORAGE_CHECKS: tuple[IOSBinaryCheckDefinition, ...] = ()
RESILIENCE_CHECKS: tuple[IOSBinaryCheckDefinition, ...] = ()
SECTION_CHECKS = (
    ("code", "Code Vulnerability", "code_evidence", CODE_CHECKS),
    ("network", "Networking", "network_evidence", NETWORK_CHECKS),
    ("data storage", "Data Storage", "data_storage_evidence", DATA_STORAGE_CHECKS),
    ("resilience", "Resilience", "resilience_evidence", RESILIENCE_CHECKS),
)
