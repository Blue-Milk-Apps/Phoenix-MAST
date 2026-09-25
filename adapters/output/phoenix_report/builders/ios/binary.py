"""Build standard report data from iOS binary post-scan output."""

from __future__ import annotations

from typing import Any, Mapping

from adapters.output.phoenix_report.builders.binary import BinaryReportDataBuilder
from adapters.output.phoenix_report.builders.ios.binary_check_catalog import (
    SECTION_CHECKS,
    IOSBinaryCheckDefinition,
)
from domain.report import (
    AppDetails,
    AssessmentStatus,
    CheckSeverity,
    EndpointDetails,
    FileDetails,
    FindingSeverity,
    HardcodedSecretDetails,
    HardcodedUrlDetails,
    HardcodedValuesDetails,
    IOSBinaryEvidenceDetails,
    IOSBinaryReportDetails,
    IOSSDKCategoryDetails,
    ManualReviewFinding,
    OverallEvaluation,
    PermissionDetails,
    ReportData,
    ReportMetadata,
    ReportPlatform,
    ReportTargetKind,
    RiskLevel,
    RiskSummary,
    SecurityCheck,
    UrlSchemeDetails,
    VulnerabilitySection,
)


class IOSBinaryReportDataBuilder(BinaryReportDataBuilder):
    """Build standard report data for iOS binary assessments."""

    _excluded_functionalities = frozenset({"fingerprint", "google cloud messaging", "infrared led"})

    @property
    def target_kind(self) -> ReportTargetKind:
        return ReportTargetKind.IOS_BINARY

    def build(self, post_scan_data: Mapping[str, Any], metadata: ReportMetadata) -> ReportData:
        """Validate the target until all iOS report sections are implemented."""

        if metadata.target.target_kind != self.target_kind:
            raise ValueError(
                "iOS binary report builder requires "
                f"target_kind={self.target_kind.value}, got {metadata.target.target_kind.value}"
            )
        sections = self._sections(post_scan_data)
        sections = self._attach_single_platform_assessments(sections, ReportPlatform.IOS)
        evaluations = tuple(
            OverallEvaluation(
                area=area,
                risk_level=self._risk_level(section),
                findings=tuple(c.name for c in section.checks if c.result == AssessmentStatus.PRESENT)
                or ("No findings identified in this scan",),
            )
            for section, (_name, area, _key, _defs) in zip(sections, SECTION_CHECKS)
        )
        return ReportData(
            metadata=metadata,
            vulnerability_sections=sections,
            overall_evaluation=evaluations,
            risk_summary=tuple(RiskSummary(area=e.area, risk_level=e.risk_level) for e in evaluations),
            findings_severity=self._finding_severity(sections),
            platform_details=self._details(post_scan_data),
        )

    @classmethod
    def _details(cls, data: Mapping[str, Any]) -> IOSBinaryReportDetails:
        manual_review_findings = cls._manual_review_findings(data)
        return IOSBinaryReportDetails(
            file_info=FileDetails(
                **{
                    k: cls._text(cls._mapping(data, "file_info"), k)
                    for k in ("filename", "size", "md5", "sha1", "sha256")
                }
            ),
            app_info=AppDetails(
                icon_path=cls._text(cls._mapping(data, "app_info"), "icon_path"),
                name=cls._text(cls._mapping(data, "app_info"), "name"),
                package_name=cls._text(cls._mapping(data, "app_info"), "package_name"),
                main_activity=cls._text(cls._mapping(data, "app_info"), "main_activity"),
                version_name=cls._text(cls._mapping(data, "app_info"), "version_name"),
                app_store_id=cls._text(cls._mapping(data, "app_info"), "app_store_id"),
                developer=cls._text(cls._mapping(data, "app_info"), "developer"),
                categories=cls._text(cls._mapping(data, "app_info"), "categories"),
                trackers_detected=cls._text(cls._mapping(data, "app_info"), "trackers_detected"),
            ),
            binary_evidence=IOSBinaryEvidenceDetails(
                **{
                    k.replace(" ", "_"): cls._optional_bool(v)
                    for k, v in cls._mapping(data, "ipa_binary_evidence").items()
                }
            ),
            url_schemes=tuple(
                UrlSchemeDetails(cls._text(x, "url_name"), tuple(x.get("schemes", ())))
                for x in data.get("url_schemes", ())
                if isinstance(x, Mapping)
            ),
            functionality=tuple(
                cls._single_platform_functionality(
                    name=k,
                    value=cls._optional_bool(v.get("present")) if isinstance(v, Mapping) else None,
                    platform=ReportPlatform.IOS,
                    explanation=cls._text(v, "explanation") if isinstance(v, Mapping) else "",
                )
                for k, v in cls._mapping(data, "functionality").items()
                if str(k).strip().casefold() not in cls._excluded_functionalities
            ),
            third_party_sdks=tuple(
                IOSSDKCategoryDetails(k, tuple(n for n, present in v.items() if present))
                for k, v in cls._mapping(data, "third_party_sdks").items()
                if isinstance(v, Mapping)
            ),
            permissions=tuple(
                PermissionDetails(
                    permission=cls._text(x, "permission"),
                    status=cls._text(x, "status"),
                    info=cls._text(x, "info"),
                    usage_description=cls._text(x, "usage_description"),
                    general_description=cls._text(x, "general_description"),
                )
                for x in data.get("permissions", ())
                if isinstance(x, Mapping)
            ),
            hardcoded_values=cls._hardcoded_values(data),
            endpoints=tuple(
                EndpointDetails(
                    endpoint=cls._text(x, "endpoint"),
                    tags=cls._text(x, "tags"),
                    ip_address=cls._text(x, "ip_address"),
                    country=cls._text(x, "country"),
                )
                for x in data.get("endpoints", ())
                if isinstance(x, Mapping)
            ),
            manual_review_available=bool(manual_review_findings),
            manual_review_status="Required" if manual_review_findings else "Not Required",
            manual_review_findings=manual_review_findings,
        )

    @classmethod
    def _manual_review_findings(cls, data: Mapping[str, Any]) -> tuple[ManualReviewFinding, ...]:
        """Expose binary checks whose evidence needs source or runtime confirmation."""

        findings: list[ManualReviewFinding] = []
        for _section_name, _area, evidence_key, definitions in SECTION_CHECKS:
            evidence_section = cls._mapping(data, evidence_key)
            for definition in definitions:
                entry = cls._mapping(evidence_section, definition.evidence_key)
                if not entry or cls._optional_bool(entry.get("present")) is not None:
                    continue
                evidence = cls._text(entry, "evidence")
                findings.append(
                    ManualReviewFinding(
                        rule_id=f"ios.binary.{definition.evidence_key}",
                        scope="iOS binary",
                        severity=definition.severity.value,
                        location=evidence if evidence.startswith("(Triage Signal") else "",
                        reason=cls._not_evaluated_explanation(entry, definition.name),
                        message=definition.name,
                    )
                )
        return tuple(findings)

    @classmethod
    def _hardcoded_values(cls, data: Mapping[str, Any]) -> HardcodedValuesDetails:
        values = cls._mapping(data, "hardcoded_values")
        urls = tuple(
            HardcodedUrlDetails(cls._text(item, "url"), cls._text(item, "country"))
            for item in values.get("urls", ())
            if isinstance(item, Mapping)
        )
        secrets = tuple(
            HardcodedSecretDetails(cls._text(item, "value") or str(item).strip())
            for item in values.get("secrets", ())
            if isinstance(item, Mapping) or str(item).strip()
        )
        emails = tuple(str(value).strip() for value in values.get("emails", ()) if str(value).strip())
        return HardcodedValuesDetails(urls=urls, emails=emails, secrets=secrets)

    @classmethod
    def _sections(cls, post_scan_data: Mapping[str, Any]) -> tuple[VulnerabilitySection, ...]:
        return tuple(
            cls._section(name, evidence_key, definitions, post_scan_data)
            for name, _area, evidence_key, definitions in SECTION_CHECKS
        )

    @classmethod
    def _section(
        cls,
        name: str,
        evidence_key: str,
        definitions: tuple[IOSBinaryCheckDefinition, ...],
        post_scan_data: Mapping[str, Any],
    ) -> VulnerabilitySection:
        return VulnerabilitySection(
            name=name,
            findings_text="",
            checks=tuple(
                cls._check(definition, cls._mapping(post_scan_data, evidence_key)) for definition in definitions
            ),
        )

    @classmethod
    def _check(
        cls,
        definition: IOSBinaryCheckDefinition,
        code_evidence: Mapping[str, Any],
    ) -> SecurityCheck:
        entry = cls._mapping(code_evidence, definition.evidence_key)
        present = cls._optional_bool(entry.get("present"))
        result = (
            AssessmentStatus.PRESENT
            if present is True
            else AssessmentStatus.NOT_PRESENT
            if present is False
            else AssessmentStatus.NOT_EVALUATED
        )
        explanation = (
            definition.present_explanation
            if result == AssessmentStatus.PRESENT
            else definition.not_present_explanation
            if result == AssessmentStatus.NOT_PRESENT
            else cls._not_evaluated_explanation(entry, definition.name)
        )
        return SecurityCheck(
            name=definition.name,
            severity=definition.severity,
            result=result,
            explanation=cls._text(entry, "explanation") or explanation,
            evidence=cls._text(entry, "evidence"),
            compliance=cls._text(entry, "compliance") or definition.compliance,
            remediation_link=cls._text(entry, "remediation_link"),
        )

    @staticmethod
    def _not_evaluated_explanation(entry: Mapping[str, Any], check_name: str = "") -> str:
        evidence = str(entry.get("evidence") or "").strip()
        if evidence == "dynamic_memory_analysis_required":
            return (
                "Not evaluated because confirming whether sensitive values remain recoverable in runtime memory "
                "requires manual review and dynamic memory inspection."
            )
        if evidence == "source_data_flow_analysis_required":
            lowered_name = check_name.lower()
            if "wifi mac" in lowered_name or "bssid" in lowered_name:
                subject = "insecure WiFi MAC/BSSID storage"
            elif "logged" in lowered_name:
                subject = "insecure logging of the identified data"
            elif "user defaults" in lowered_name:
                subject = "sensitive data storage in UserDefaults"
            else:
                subject = "the identified storage behavior"
            return f"Not evaluated because confirming {subject} requires source-level data-flow analysis."
        if evidence == "source_permission_api_analysis_required":
            return (
                "Not evaluated because confirming global write access requires source-level review of the "
                "permission-setting API and its effective access scope."
            )
        if evidence == "source_input_configuration_analysis_required":
            return (
                "Not evaluated because determining whether text input can expose sensitive values through the "
                "keyboard cache requires source-level input configuration review."
            )
        if evidence == "source_control_flow_and_runtime_authentication_testing_required":
            return (
                "Not evaluated because determining whether biometric or local authentication can be bypassed "
                "requires source-level control-flow review and runtime authentication testing."
            )
        if evidence.startswith("(Triage Signal; source review required)"):
            return (
                "Not evaluated because binary strings only indicate related data and storage or logging names; "
                "source-level data-flow review is required to confirm their use."
            )
        detail = str(entry.get("not_evaluated_detail") or entry.get("not_evaluated_reason") or "").strip()
        if detail:
            return f"Not evaluated because {detail.rstrip('.')}."
        if not entry:
            return "Not evaluated because post-scan analysis did not produce evidence for this check."
        return "Not evaluated because the scanner did not return a conclusive result."

    @staticmethod
    def _finding_severity(sections: tuple[VulnerabilitySection, ...]) -> FindingSeverity:
        counts = {severity: 0 for severity in CheckSeverity}
        for section in sections:
            for check in section.checks:
                if check.result == AssessmentStatus.PRESENT:
                    counts[check.severity] += 1
        return FindingSeverity(
            **{
                severity.value: counts[severity]
                for severity in (
                    CheckSeverity.CRITICAL,
                    CheckSeverity.HIGH,
                    CheckSeverity.MEDIUM,
                    CheckSeverity.LOW,
                    CheckSeverity.INFO,
                    CheckSeverity.SECURE,
                )
            }
        )

    @staticmethod
    def _risk_level(section: VulnerabilitySection) -> RiskLevel:
        evaluated = tuple(check for check in section.checks if check.result != AssessmentStatus.NOT_EVALUATED)
        if not evaluated:
            return RiskLevel.NOT_EVALUATED
        present = [check.severity for check in evaluated if check.result == AssessmentStatus.PRESENT]
        if CheckSeverity.CRITICAL in present:
            return RiskLevel.CRITICAL
        if CheckSeverity.HIGH in present:
            return RiskLevel.HIGH
        if CheckSeverity.MEDIUM in present:
            return RiskLevel.MEDIUM
        return RiskLevel.LOW

    @staticmethod
    def _mapping(data: Mapping[str, Any], key: str) -> Mapping[str, Any]:
        value = data.get(key)
        return value if isinstance(value, Mapping) else {}

    @staticmethod
    def _optional_bool(value: Any) -> bool | None:
        if value is True or str(value).strip().lower() == "true":
            return True
        if value is False or str(value).strip().lower() == "false":
            return False
        return None

    @staticmethod
    def _text(data: Mapping[str, Any], key: str) -> str:
        return str(data.get(key) or "").strip()
