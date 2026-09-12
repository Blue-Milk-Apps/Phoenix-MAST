"""Format-independent models for security assessment reports."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from enum import StrEnum


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


class ReportPlatform(StrEnum):
    """Normalized platform represented by report metadata."""

    ANDROID = "android"
    IOS = "ios"
    FLUTTER = "flutter"
    REACT_NATIVE = "react_native"


class ReportTargetType(StrEnum):
    """Target form assessed by a report."""

    BINARY = "binary"
    SOURCE = "source"


class ReportStack(StrEnum):
    """Normalized technology stack for a source target."""

    FLUTTER = "flutter"
    REACT_NATIVE = "react_native"
    NATIVE_ANDROID = "native_android"
    NATIVE_IOS = "native_ios"


class ReportTargetKind(StrEnum):
    """Supported assessment target families."""

    ANDROID_BINARY = "android_binary"
    IOS_BINARY = "ios_binary"
    FLUTTER_SOURCE = "flutter_source"
    REACT_NATIVE_SOURCE = "react_native_source"
    NATIVE_ANDROID_SOURCE = "native_android_source"
    NATIVE_IOS_SOURCE = "native_ios_source"


@dataclass(frozen=True)
class ReportTarget:
    """Canonical target classification for a report."""

    target_kind: ReportTargetKind
    platform: ReportPlatform
    target_type: ReportTargetType
    stack: ReportStack | None


@dataclass(frozen=True)
class ReportMetadata:
    """Common identifying metadata for an assessment report."""

    target: ReportTarget
    app_display_name: str = ""
    file_name: str = ""
    package_name: str = ""
    scan_date: str = ""
    version_name: str = ""
    version_code: str = ""
    reviewer_org: str = ""


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


class PlatformReportDetails(ABC):
    """Platform-specific report content emitted by a report data builder."""

    @property
    @abstractmethod
    def target_kind(self) -> ReportTargetKind:
        """Return the target kind this detail model represents."""


@dataclass(frozen=True)
class ReportData:
    """Standard, format-independent output of a report data builder."""

    metadata: ReportMetadata
    vulnerability_sections: tuple[VulnerabilitySection, ...]
    overall_evaluation: tuple[OverallEvaluation, ...]
    risk_summary: tuple[RiskSummary, ...]
    findings_severity: FindingSeverity
    platform_details: PlatformReportDetails
