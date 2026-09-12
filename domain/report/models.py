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
class SignatureVersions:
    """Verified Android application signature schemes."""

    v1: bool = False
    v2: bool = False
    v3: bool = False
    v4: bool = False


@dataclass(frozen=True)
class CertificateDetails:
    """Application signing certificate details."""

    owner_name: str = ""
    organization: str = ""
    organizational_unit: str = ""
    location: str = ""
    validity: str = ""
    issuer: str = ""
    serial_number: str = ""
    signature_versions: SignatureVersions = SignatureVersions()
    hash_algorithms: str = ""
    fingerprint: str = ""
    unique_certs: str = ""


@dataclass(frozen=True)
class FileDetails:
    """Analyzed application file details."""

    filename: str = ""
    size: str = ""
    md5: str = ""
    sha1: str = ""
    sha256: str = ""


@dataclass(frozen=True)
class AppDetails:
    """Application identity and SDK details."""

    icon_path: str = ""
    name: str = ""
    package_name: str = ""
    main_activity: str = ""
    target_sdk: str = ""
    min_sdk: str = ""
    max_sdk: str = ""
    version_name: str = ""
    app_store_id: str = ""
    developer: str = ""
    categories: str = ""
    trackers_detected: str = ""


@dataclass(frozen=True)
class AndroidApplicationDetails:
    """Android manifest application security settings."""

    debuggable: bool | None = None
    allow_backup: bool | None = None
    uses_cleartext_traffic: bool | None = None


@dataclass(frozen=True)
class AppComponentSummary:
    """Counts of Android application components."""

    activities: int = 0
    services: int = 0
    receivers: int = 0
    providers: int = 0
    exported_activities: int = 0
    exported_services: int = 0
    exported_receivers: int = 0
    exported_providers: int = 0


@dataclass(frozen=True)
class PermissionDetails:
    """A requested application permission."""

    permission: str
    status: str = ""
    info: str = ""
    usage_description: str = ""
    general_description: str = ""


@dataclass(frozen=True)
class FunctionalityDetails:
    """Observed application functionality."""

    name: str
    present: bool | None
    explanation: str = ""


@dataclass(frozen=True)
class HardcodedUrlDetails:
    """A hardcoded URL found in application content."""

    url: str
    country: str = ""


@dataclass(frozen=True)
class HardcodedSecretDetails:
    """A hardcoded secret found in application content."""

    value: str


@dataclass(frozen=True)
class HardcodedValuesDetails:
    """Hardcoded values found in application content."""

    urls: tuple[HardcodedUrlDetails, ...] = ()
    emails: tuple[str, ...] = ()
    secrets: tuple[HardcodedSecretDetails, ...] = ()


@dataclass(frozen=True)
class EndpointDetails:
    """A network endpoint observed in application content."""

    endpoint: str
    tags: str = ""
    ip_address: str = ""
    country: str = ""


@dataclass(frozen=True)
class AndroidBinaryReportDetails(PlatformReportDetails):
    """Android-binary-specific content for a report."""

    certificate: CertificateDetails
    file_info: FileDetails
    app_info: AppDetails
    application: AndroidApplicationDetails
    app_components: AppComponentSummary
    functionality: tuple[FunctionalityDetails, ...]
    permissions: tuple[PermissionDetails, ...]
    hardcoded_values: HardcodedValuesDetails
    endpoints: tuple[EndpointDetails, ...]

    @property
    def target_kind(self) -> ReportTargetKind:
        return ReportTargetKind.ANDROID_BINARY


@dataclass(frozen=True)
class ReportData:
    """Standard, format-independent output of a report data builder."""

    metadata: ReportMetadata
    vulnerability_sections: tuple[VulnerabilitySection, ...]
    overall_evaluation: tuple[OverallEvaluation, ...]
    risk_summary: tuple[RiskSummary, ...]
    findings_severity: FindingSeverity
    platform_details: PlatformReportDetails
