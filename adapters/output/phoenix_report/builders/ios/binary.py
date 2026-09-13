"""Build standard report data from iOS binary post-scan output."""

from __future__ import annotations

from typing import Any, Mapping

from adapters.output.phoenix_report.builders.ios.binary_check_catalog import (
    SECTION_CHECKS,
    IOSBinaryCheckDefinition,
)
from domain.report import (
    AppDetails,
    CheckResult,
    CheckSeverity,
    EndpointDetails,
    FileDetails,
    FindingSeverity,
    FunctionalityDetails,
    HardcodedSecretDetails,
    HardcodedUrlDetails,
    HardcodedValuesDetails,
    IOSBinaryEvidenceDetails,
    IOSBinaryReportDetails,
    IOSSDKCategoryDetails,
    IOSUrlSchemeDetails,
    OverallEvaluation,
    PermissionDetails,
    ReportData,
    ReportMetadata,
    ReportTargetKind,
    RiskLevel,
    RiskSummary,
    SecurityCheck,
    VulnerabilitySection,
)
from ports.report_data_builder_port import ReportDataBuilderPort


class IOSBinaryReportDataBuilder(ReportDataBuilderPort):
    """Build standard report data for iOS binary assessments."""

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
        evaluations = tuple(
            OverallEvaluation(
                area=area,
                risk_level=self._risk_level(section),
                findings=tuple(c.name for c in section.checks if c.result == CheckResult.PRESENT)
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
                IOSUrlSchemeDetails(cls._text(x, "url_name"), tuple(x.get("schemes", ())))
                for x in data.get("url_schemes", ())
                if isinstance(x, Mapping)
            ),
            functionality=tuple(
                FunctionalityDetails(k, cls._optional_bool(v.get("present")) if isinstance(v, Mapping) else None)
                for k, v in cls._mapping(data, "functionality").items()
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
        )

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
            CheckResult.PRESENT
            if present is True
            else CheckResult.NOT_PRESENT
            if present is False
            else CheckResult.NOT_EVALUATED
        )
        explanation = (
            definition.present_explanation
            if result == CheckResult.PRESENT
            else definition.not_present_explanation
            if result == CheckResult.NOT_PRESENT
            else f"{definition.name} was not evaluated because scan evidence is unavailable."
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
    def _finding_severity(sections: tuple[VulnerabilitySection, ...]) -> FindingSeverity:
        counts = {severity: 0 for severity in CheckSeverity}
        for section in sections:
            for check in section.checks:
                if check.result == CheckResult.PRESENT:
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
        present = [check.severity for check in section.checks if check.result == CheckResult.PRESENT]
        if not present:
            return RiskLevel.NOT_EVALUATED
        if CheckSeverity.CRITICAL in present or CheckSeverity.HIGH in present:
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
