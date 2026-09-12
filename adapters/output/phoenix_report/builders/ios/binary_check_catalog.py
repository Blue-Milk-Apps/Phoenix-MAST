"""Canonical iOS binary security checks and their evidence bindings."""

from __future__ import annotations

from dataclasses import dataclass

from domain.report import CheckSeverity


@dataclass(frozen=True)
class IOSBinaryCheckDefinition:
    """A canonical check included in every iOS binary report."""

    name: str
    severity: CheckSeverity
    evidence_key: str
    compliance: str
    present_explanation: str
    not_present_explanation: str
    aliases: tuple[str, ...] = ()


def _code(name: str, severity: CheckSeverity, key: str) -> IOSBinaryCheckDefinition:
    return IOSBinaryCheckDefinition(name, severity, key, "", f"{name} was identified.", f"{name} was not identified.")


CODE_CHECKS = (
    _code("Deprecated API - UIWebView", CheckSeverity.MEDIUM, "uses_uiwebview"),
    _code("Insecure Nanopb Library", CheckSeverity.HIGH, "insecure_nanopb_library"),
    _code("Insecure Serialization API - NSKeyedUnarchiver", CheckSeverity.HIGH, "insecure_nskeyedunarchiver_usage"),
    _code("Missing ARC Binary Protections", CheckSeverity.MEDIUM, "missing_arc"),
    _code("Position-Independent Code (PIC) Not Enabled", CheckSeverity.MEDIUM, "pic_not_enabled"),
    _code("Stack Canaries Not Enabled", CheckSeverity.MEDIUM, "stack_canaries_not_enabled"),
    _code("Insecure API Usage in Binary", CheckSeverity.MEDIUM, "insecure_api_usage_in_binary"),
    _code("Usage of malloc Instead of calloc in Binary", CheckSeverity.MEDIUM, "malloc_instead_of_calloc"),
    _code(
        "Application Encodes Data Using Insecure Cryptography",
        CheckSeverity.HIGH,
        "encodes_data_using_insecure_cryptography",
    ),
    _code("Application Utilizes Insecure Cryptography", CheckSeverity.HIGH, "utilizes_insecure_cryptography"),
    _code("PBKDF2 Iteration Count <10k", CheckSeverity.MEDIUM, "pbkdf2_iteration_count_below_10k"),
    _code("Hardcoded API Keys within the Application Bundle", CheckSeverity.HIGH, "hardcoded_api_keys_in_bundle"),
    _code("Potentially Insecure iOS Entitlements", CheckSeverity.MEDIUM, "insecure_entitlements"),
)
NETWORK_CHECKS: tuple[IOSBinaryCheckDefinition, ...] = ()
DATA_STORAGE_CHECKS: tuple[IOSBinaryCheckDefinition, ...] = ()
RESILIENCE_CHECKS: tuple[IOSBinaryCheckDefinition, ...] = ()

SECTION_CHECKS = (
    ("code", "Code Vulnerability", "code_evidence", CODE_CHECKS),
    ("network", "Networking", "network_evidence", NETWORK_CHECKS),
    ("data storage", "Data Storage", "data_storage_evidence", DATA_STORAGE_CHECKS),
    ("resilience", "Resilience", "resilience_evidence", RESILIENCE_CHECKS),
)
