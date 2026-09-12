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


CODE_CHECKS: tuple[IOSBinaryCheckDefinition, ...] = ()
NETWORK_CHECKS: tuple[IOSBinaryCheckDefinition, ...] = ()
DATA_STORAGE_CHECKS: tuple[IOSBinaryCheckDefinition, ...] = ()
RESILIENCE_CHECKS: tuple[IOSBinaryCheckDefinition, ...] = ()

SECTION_CHECKS = (
    ("code", "Code Vulnerability", "code_evidence", CODE_CHECKS),
    ("network", "Networking", "network_evidence", NETWORK_CHECKS),
    ("data storage", "Data Storage", "data_storage_evidence", DATA_STORAGE_CHECKS),
    ("resilience", "Resilience", "resilience_evidence", RESILIENCE_CHECKS),
)
