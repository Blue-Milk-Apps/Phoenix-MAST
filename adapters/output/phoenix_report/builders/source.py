"""Shared implementation boundary for source report builders."""

from abc import ABC
from dataclasses import dataclass
from typing import Any, ClassVar, Mapping

from domain.report import (
    AssessmentStatus,
    CheckResult,
    CheckSeverity,
    FindingSeverity,
    FunctionalityDetails,
    OverallEvaluation,
    PlatformAssessment,
    ReportData,
    ReportMetadata,
    ReportPlatform,
    RiskLevel,
    RiskSummary,
    SecurityCheck,
    VulnerabilitySection,
)
from ports.report_data_builder_port import ReportDataBuilderPort


@dataclass(frozen=True)
class SourceCheckDefinition:
    """Metadata needed to render a source security check."""

    name: str
    evidence_key: str
    severity: CheckSeverity
    compliance: str = ""
    present_explanation: str = ""
    not_present_explanation: str = ""


class SourceReportDataBuilder(ReportDataBuilderPort, ABC):
    """Base for Flutter, React Native, and native source builders."""

    check_sections: ClassVar[tuple[tuple[str, str, tuple[SourceCheckDefinition, ...]], ...]] = ()

    def build(self, post_scan_data: Mapping[str, Any], metadata: ReportMetadata) -> ReportData:
        if metadata.target.target_kind != self.target_kind:
            raise ValueError(f"Source report builder requires target_kind={self.target_kind.value}")
        if self.check_sections:
            sections = tuple(
                self._catalog_section(name, key, definitions, post_scan_data)
                for name, key, definitions in self.check_sections
            )
        else:
            sections = tuple(
                self._section(name, key, post_scan_data)
                for name, key in (
                    ("Code", "code_evidence"),
                    ("Network", "network_evidence"),
                    ("Data Storage", "data_storage_evidence"),
                    ("Resilience", "resilience_evidence"),
                )
            )
        evaluations = tuple(
            OverallEvaluation(
                area=name,
                risk_level=self._risk(section),
                findings=tuple(check.name for check in section.checks if check.result == CheckResult.PRESENT)
                or ("No findings identified in this scan",),
            )
            for section, name in zip(sections, ("Code Vulnerability", "Networking", "Data Storage", "Resilience"))
        )
        return ReportData(
            metadata,
            sections,
            evaluations,
            tuple(RiskSummary(e.area, e.risk_level) for e in evaluations),
            self._severity(sections),
            self._build_details(post_scan_data),
        )

    @classmethod
    def _section(cls, name: str, key: str, data: Mapping[str, Any]) -> VulnerabilitySection:
        evidence = data.get(key) if isinstance(data.get(key), Mapping) else {}
        checks = tuple(
            cls._check(name, str(check_name), value)
            for check_name, value in evidence.items()
            if isinstance(value, Mapping)
        )
        return VulnerabilitySection(name=name, findings_text="", checks=checks)

    @classmethod
    def _catalog_section(
        cls,
        name: str,
        key: str,
        definitions: tuple[SourceCheckDefinition, ...],
        data: Mapping[str, Any],
    ) -> VulnerabilitySection:
        evidence = data.get(key) if isinstance(data.get(key), Mapping) else {}
        return VulnerabilitySection(
            name=name,
            findings_text="",
            checks=tuple(cls._catalog_check(definition, evidence) for definition in definitions),
        )

    @classmethod
    def _catalog_check(
        cls,
        definition: SourceCheckDefinition,
        evidence: Mapping[str, Any],
    ) -> SecurityCheck:
        entry = evidence.get(definition.evidence_key)
        entry = entry if isinstance(entry, Mapping) else {}
        present = entry.get("present")
        result = (
            CheckResult.PRESENT
            if present is True
            else CheckResult.NOT_PRESENT
            if present is False
            else CheckResult.NOT_EVALUATED
        )
        explanation = str(entry.get("explanation") or "")
        if not explanation:
            explanation = (
                definition.present_explanation
                if result == CheckResult.PRESENT
                else definition.not_present_explanation
                if result == CheckResult.NOT_PRESENT
                else f"{definition.name} was not evaluated because the required scan evidence is unavailable."
            )
        return SecurityCheck(
            name=definition.name,
            severity=definition.severity,
            result=result,
            explanation=explanation,
            evidence=str(entry.get("evidence") or ""),
            compliance=str(entry.get("compliance") or definition.compliance),
            remediation_link=str(entry.get("remediation_link") or ""),
        )

    @staticmethod
    def _check(section_name: str, name: str, value: Mapping[str, Any]) -> SecurityCheck:
        present = value.get("present")
        result = (
            CheckResult.PRESENT
            if present is True
            else CheckResult.NOT_PRESENT
            if present is False
            else CheckResult.NOT_EVALUATED
        )
        severity = str(value.get("severity", "info")).lower()
        check_severity = next((item for item in CheckSeverity if item.value == severity), CheckSeverity.INFO)
        display_name = SourceReportDataBuilder._display_name(name)
        explanation = str(value.get("explanation") or "")
        if not explanation:
            explanation = SourceReportDataBuilder._default_explanation(display_name, result)
        compliance = str(value.get("compliance") or "")
        if not compliance:
            compliance = SourceReportDataBuilder._default_compliance(section_name)
        return SecurityCheck(
            name=display_name,
            severity=check_severity,
            result=result,
            explanation=explanation,
            evidence=str(value.get("evidence") or ""),
            compliance=compliance,
            remediation_link=str(value.get("remediation_link") or ""),
        )

    @staticmethod
    def _display_name(name: str) -> str:
        """Convert scanner keys into readable check names for the report."""

        if "_" not in name:
            return name
        display_name = " ".join(name.replace("_", " ").split()).title()
        for title_case, preferred_case in (
            ("Api", "API"),
            ("Ats", "ATS"),
            ("Ftp", "FTP"),
            ("Gps", "GPS"),
            ("Http", "HTTP"),
            ("Https", "HTTPS"),
            ("Id", "ID"),
            ("Imei", "IMEI"),
            ("Ios", "iOS"),
            ("Mitm", "MitM"),
            ("Openssl", "OpenSSL"),
            ("Pbkdf2", "PBKDF2"),
            ("Pic", "PIC"),
            ("Sql", "SQL"),
            ("Tls", "TLS"),
            ("Uiwebview", "UIWebView"),
            ("Wifi", "WiFi"),
            ("X509trustmanager", "X509TrustManager"),
        ):
            display_name = display_name.replace(title_case, preferred_case)
        return display_name

    @staticmethod
    def _default_explanation(name: str, result: CheckResult) -> str:
        if result == CheckResult.PRESENT:
            return f"Evidence indicates that {name.lower()}."
        if result == CheckResult.NOT_PRESENT:
            return f"No evidence indicates that {name.lower()}."
        return f"{name} was not evaluated because the required scan evidence is unavailable."

    @staticmethod
    def _default_compliance(section_name: str) -> str:
        return {
            "Code": "MASVS-CODE",
            "Network": "MASVS-NETWORK",
            "Data Storage": "MASVS-STORAGE",
            "Resilience": "MASVS-RESILIENCE",
        }.get(section_name, "MASVS")

    @staticmethod
    def _risk(section: VulnerabilitySection) -> RiskLevel:
        assessed_checks = tuple(check for check in section.checks if check.result != CheckResult.NOT_EVALUATED)
        if not assessed_checks:
            return RiskLevel.NOT_EVALUATED

        present_severities = {check.severity for check in assessed_checks if check.result == CheckResult.PRESENT}
        if CheckSeverity.CRITICAL in present_severities:
            return RiskLevel.CRITICAL

        if CheckSeverity.HIGH in present_severities:
            return RiskLevel.HIGH

        has_medium_risk_finding = CheckSeverity.MEDIUM in present_severities
        if has_medium_risk_finding:
            return RiskLevel.MEDIUM

        return RiskLevel.LOW

    @staticmethod
    def _severity(sections: tuple[VulnerabilitySection, ...]) -> FindingSeverity:
        counts = {severity: 0 for severity in ("critical", "high", "medium", "low", "info", "secure")}
        for section in sections:
            for check in section.checks:
                if check.result == CheckResult.PRESENT:
                    counts[check.severity.value] += 1
        return FindingSeverity(**counts)

    def _build_details(self, data: Mapping[str, Any]):
        raise NotImplementedError

    @staticmethod
    def _single_platform_functionality(
        name: object,
        value: Mapping[str, Any],
        platform: ReportPlatform,
    ) -> FunctionalityDetails:
        present = value.get("present")
        status = (
            AssessmentStatus.PRESENT
            if present is True
            else AssessmentStatus.NOT_PRESENT
            if present is False
            else AssessmentStatus.NOT_EVALUATED
        )
        explanation = str(value.get("explanation") or "")
        assessment = PlatformAssessment(platform=platform, status=status, explanation=explanation)
        return FunctionalityDetails(
            name=str(name),
            present=present,
            explanation=explanation,
            platform_assessments=(assessment,),
            status=status,
        )
