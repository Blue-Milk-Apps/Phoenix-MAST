"""Format-independent models for security assessment reports."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Iterable


class RiskLevel(StrEnum):
    """Overall risk assigned to a report area."""

    CRITICAL = "critical"
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


class AssessmentStatus(StrEnum):
    """Outcome of assessing one report item on one platform."""

    PRESENT = "present"
    NOT_PRESENT = "not_present"
    PARTIAL = "partial"
    NOT_EVALUATED = "not_evaluated"
    NOT_APPLICABLE = "not_applicable"

    @classmethod
    def aggregate(cls, statuses: Iterable["AssessmentStatus"]) -> "AssessmentStatus":
        """Combine platform outcomes into one report-level outcome."""

        applicable = tuple(status for status in statuses if status != cls.NOT_APPLICABLE)
        if not applicable:
            return cls.NOT_APPLICABLE
        if cls.PRESENT in applicable:
            return cls.PRESENT
        if all(status == cls.NOT_PRESENT for status in applicable):
            return cls.NOT_PRESENT
        if all(status == cls.NOT_EVALUATED for status in applicable):
            return cls.NOT_EVALUATED
        return cls.PARTIAL


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
    app_icon_path: str = ""
    app_icon_data_uri: str = ""


@dataclass(frozen=True)
class PlatformAssessment:
    """Assessment outcome and supporting details for one platform."""

    platform: ReportPlatform
    status: AssessmentStatus
    explanation: str = ""
    evidence: tuple[str, ...] = ()


@dataclass(frozen=True)
class SecurityCheck:
    """A single assessed security control."""

    name: str
    severity: CheckSeverity
    result: AssessmentStatus
    explanation: str
    evidence: str = ""
    compliance: str = ""
    remediation_link: str = ""
    platform_assessments: tuple[PlatformAssessment, ...] = ()
    status: AssessmentStatus | None = None
    rule_id: str = ""
    finding_type: str = ""
    scope: str = ""
    impact: str = ""
    remediation: str = ""
    references: tuple[str, ...] = ()
    execution_status: str = ""
    rule_file: str = ""


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
class FlutterPlatformPresentation:
    """One generated platform row in the Flutter project inventory."""

    name: str
    detected: bool = False
    metadata_status: str = "Not Assessed"
    identifier: str = ""
    version: str = ""
    requirements: str = ""


@dataclass(frozen=True)
class FlutterDeclaredDependency:
    """A dependency declared by a Flutter project."""

    name: str
    constraint: str = ""
    scope: str = ""
    source: str = ""


@dataclass(frozen=True)
class FlutterResolvedDependency:
    """A dependency resolved by Flutter tooling."""

    name: str
    version: str = ""
    dependency_kind: str = ""
    source: str = ""


@dataclass(frozen=True)
class FlutterSbomPackage:
    """A package emitted by the source scan SBOM."""

    name: str
    version: str = ""
    output_path: str = ""


@dataclass(frozen=True)
class FlutterDependencyPresentation:
    """Declared, resolved, and SBOM dependency views for the PDF."""

    metadata_status: str = "Not Assessed"
    sbom_status: str = "Not Assessed"
    declared: tuple[FlutterDeclaredDependency, ...] = ()
    resolved: tuple[FlutterResolvedDependency, ...] = ()
    sbom_packages: tuple[FlutterSbomPackage, ...] = ()


@dataclass(frozen=True)
class FlutterDeepLink:
    """An Android deep-link row projected into a Flutter report."""

    uri: str = ""
    component: str = ""
    mime_type: str = ""


@dataclass(frozen=True)
class FlutterUrlScheme:
    """An iOS URL-scheme declaration in a Flutter project."""

    url_name: str = ""
    schemes: tuple[str, ...] = ()


@dataclass(frozen=True)
class ManualReviewFinding:
    """A raw finding retained for manual review."""

    rule_id: str = ""
    scope: str = ""
    severity: str = ""
    location: str = ""
    reason: str = ""
    message: str = ""


@dataclass(frozen=True)
class FlutterManualReviewFinding(ManualReviewFinding):
    """A finding retained for Flutter manual review."""


@dataclass(frozen=True)
class FlutterPresentationDetails:
    """Flutter inventory and manual-review data needed by PDF templates."""

    extraction_status: str = "Not Assessed"
    dart_sdk_constraint: str = ""
    flutter_sdk_constraint: str = ""
    android_application_id: str = ""
    ios_bundle_identifier: str = ""
    description: str = ""
    homepage: str = ""
    repository: str = ""
    warnings: tuple[str, ...] = ()
    platforms: tuple[FlutterPlatformPresentation, ...] = ()
    dependencies: FlutterDependencyPresentation = FlutterDependencyPresentation()
    deep_links_assessed: bool = False
    deep_links: tuple[FlutterDeepLink, ...] = ()
    url_schemes_assessed: bool = False
    url_schemes: tuple[FlutterUrlScheme, ...] = ()
    queried_url_schemes: tuple[str, ...] = ()
    manual_review_available: bool = False
    manual_review_status: str = "Not Assessed"
    manual_review_findings: tuple[FlutterManualReviewFinding, ...] = ()


@dataclass(frozen=True)
class FlutterReportDetails(PlatformReportDetails):
    """Flutter-source-specific content for a report."""

    package_name: str = ""
    version_name: str = ""
    dart_constraint: str = ""
    flutter_constraint: str = ""
    supported_platforms: tuple[str, ...] = ()
    dependencies: tuple["FlutterDependencyDetails", ...] = ()
    functionality: tuple[FunctionalityDetails, ...] = ()
    permissions: tuple[PermissionDetails, ...] = ()
    hardcoded_values: HardcodedValuesDetails = field(default_factory=lambda: HardcodedValuesDetails())
    endpoints: tuple[EndpointDetails, ...] = ()
    presentation: FlutterPresentationDetails = FlutterPresentationDetails()

    @property
    def target_kind(self) -> ReportTargetKind:
        return ReportTargetKind.FLUTTER_SOURCE


@dataclass(frozen=True)
class FlutterDependencyDetails:
    name: str
    version: str = ""
    constraint: str = ""
    source: str = ""
    group: str = ""


@dataclass(frozen=True)
class ReactNativeRuntimeDetails:
    react_native_constraint: str = ""
    expo_constraint: str = ""


@dataclass(frozen=True)
class ReactNativePlatformDetails:
    android_detected: bool = False
    ios_detected: bool = False


@dataclass(frozen=True)
class ReactNativeReportDetails(PlatformReportDetails):
    package_name: str = ""
    version_name: str = ""
    runtime: ReactNativeRuntimeDetails = ReactNativeRuntimeDetails()
    platforms: ReactNativePlatformDetails = ReactNativePlatformDetails()
    dependencies: tuple[FlutterDependencyDetails, ...] = ()
    functionality: tuple[FunctionalityDetails, ...] = ()
    permissions: tuple[PermissionDetails, ...] = ()
    hardcoded_values: HardcodedValuesDetails = field(default_factory=lambda: HardcodedValuesDetails())
    endpoints: tuple[EndpointDetails, ...] = ()

    @property
    def target_kind(self) -> ReportTargetKind:
        return ReportTargetKind.REACT_NATIVE_SOURCE


@dataclass(frozen=True)
class NativeAndroidReportDetails(PlatformReportDetails):
    package_name: str = ""
    version_name: str = ""
    target_sdk: str = ""
    min_sdk: str = ""
    application: AndroidApplicationDetails = field(default_factory=lambda: AndroidApplicationDetails())
    app_components: AppComponentSummary = field(default_factory=lambda: AppComponentSummary())
    functionality: tuple[FunctionalityDetails, ...] = ()
    permissions: tuple[PermissionDetails, ...] = ()
    hardcoded_values: HardcodedValuesDetails = field(default_factory=lambda: HardcodedValuesDetails())
    endpoints: tuple[EndpointDetails, ...] = ()
    url_schemes: tuple[UrlSchemeDetails, ...] = ()

    @property
    def target_kind(self) -> ReportTargetKind:
        return ReportTargetKind.NATIVE_ANDROID_SOURCE


@dataclass(frozen=True)
class NativeIOSReportDetails(PlatformReportDetails):
    bundle_identifier: str = ""
    version_name: str = ""
    minimum_os: str = ""
    url_schemes: tuple[UrlSchemeDetails, ...] = ()
    functionality: tuple[FunctionalityDetails, ...] = ()
    permissions: tuple[PermissionDetails, ...] = ()
    hardcoded_values: HardcodedValuesDetails = field(default_factory=lambda: HardcodedValuesDetails())
    endpoints: tuple[EndpointDetails, ...] = ()
    third_party_sdks: tuple[str, ...] = ()
    manual_review_available: bool = False
    manual_review_status: str = "Not Assessed"
    manual_review_findings: tuple[ManualReviewFinding, ...] = ()

    @property
    def target_kind(self) -> ReportTargetKind:
        return ReportTargetKind.NATIVE_IOS_SOURCE


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
    platform_assessments: tuple[PlatformAssessment, ...] = ()
    status: AssessmentStatus | None = None


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
class IOSBinaryEvidenceDetails:
    """iOS executable protection evidence."""

    nx: bool | None = None
    pie: bool | None = None
    stack_canary: bool | None = None
    arc: bool | None = None
    rpath: bool | None = None
    code_signature: bool | None = None
    encrypted: bool | None = None
    symbols_stripped: bool | None = None


@dataclass(frozen=True)
class UrlSchemeDetails:
    """A declared custom URL or URI scheme handler."""

    url_name: str
    schemes: tuple[str, ...] = ()


@dataclass(frozen=True)
class IOSSDKCategoryDetails:
    """Detected third-party SDKs in one category."""

    category: str
    sdk_names: tuple[str, ...] = ()


@dataclass(frozen=True)
class IOSBinaryReportDetails(PlatformReportDetails):
    """iOS-binary-specific content for a report."""

    file_info: FileDetails
    app_info: AppDetails
    binary_evidence: IOSBinaryEvidenceDetails
    url_schemes: tuple[UrlSchemeDetails, ...]
    functionality: tuple[FunctionalityDetails, ...]
    third_party_sdks: tuple[IOSSDKCategoryDetails, ...]
    permissions: tuple[PermissionDetails, ...]
    hardcoded_values: HardcodedValuesDetails
    endpoints: tuple[EndpointDetails, ...]
    manual_review_available: bool = False
    manual_review_status: str = "Not Assessed"
    manual_review_findings: tuple[ManualReviewFinding, ...] = ()

    @property
    def target_kind(self) -> ReportTargetKind:
        return ReportTargetKind.IOS_BINARY


@dataclass(frozen=True)
class SecretFindingSummary:
    detector: str
    location: str
    verification: str = "Not checked"


@dataclass(frozen=True)
class SecretScanSummary:
    scanner: str
    status: str
    findings: tuple[SecretFindingSummary, ...] = ()
    reason: str = ""


@dataclass(frozen=True)
class ReportData:
    """Standard, format-independent output of a report data builder."""

    metadata: ReportMetadata
    vulnerability_sections: tuple[VulnerabilitySection, ...]
    overall_evaluation: tuple[OverallEvaluation, ...]
    risk_summary: tuple[RiskSummary, ...]
    findings_severity: FindingSeverity
    platform_details: PlatformReportDetails
    rule_coverage: tuple[dict[str, object], ...] = ()
    rule_status: str = ""
    rule_status_reason: str = ""
    secret_scans: tuple[SecretScanSummary, ...] = ()
