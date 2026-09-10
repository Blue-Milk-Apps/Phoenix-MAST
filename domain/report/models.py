"""Format-independent models for security assessment reports."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any, Mapping


class RiskLevel(StrEnum):
    """Overall risk assigned to a report area."""

    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    NOT_EVALUATED = "not_evaluated"


class CheckSeverity(StrEnum):
    """Severity assigned to an individual security check."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"
    SECURE = "secure"
    HOTSPOT = "hotspot"
    VARIABLE = "variable"
    NOT_APPLICABLE = "not_applicable"


class CheckResult(StrEnum):
    """Assessment outcome for an individual security check."""

    PRESENT = "present"
    NOT_PRESENT = "not_present"
    NOT_EVALUATED = "not_evaluated"


@dataclass(frozen=True)
class ReportAssessmentScope:
    """Assessment facts that determine report applicability."""

    platform: str
    target_type: str
    assessed_sections: tuple[str, ...]


@dataclass(frozen=True)
class SecurityCheck:
    """A single assessed security control."""

    name: str
    severity: CheckSeverity
    result: CheckResult
    explanation: str
    evidence: str = ""
    compliance: str = ""
    remediation_link: str = ""


@dataclass(frozen=True)
class VulnerabilitySection:
    """Security checks and findings for one assessment area."""

    name: str
    findings_text: str
    checks: tuple[SecurityCheck, ...]


@dataclass(frozen=True)
class OverallEvaluation:
    """Overall risk and findings for one assessment area."""

    area: str
    risk_level: RiskLevel
    findings: tuple[str, ...]


@dataclass(frozen=True)
class RiskSummary:
    """Risk level for one area in a report summary."""

    area: str
    risk_level: RiskLevel


@dataclass(frozen=True)
class FindingSeverity:
    """Counts of checks grouped by severity."""

    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    info: int = 0
    secure: int = 0


@dataclass(frozen=True)
class ReportData:
    """Standard, format-independent output of a report data builder."""

    scope: ReportAssessmentScope
    metadata: Mapping[str, Any]
    vulnerability_sections: tuple[VulnerabilitySection, ...]
    overall_evaluation: tuple[OverallEvaluation, ...]
    risk_summary: tuple[RiskSummary, ...]
    findings_severity: FindingSeverity
    details: Mapping[str, Any] = field(default_factory=dict)
