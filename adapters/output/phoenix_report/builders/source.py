"""Shared implementation boundary for source report builders."""

from abc import ABC
from typing import Any, Mapping

from domain.report import (
    CheckResult,
    CheckSeverity,
    FindingSeverity,
    OverallEvaluation,
    ReportData,
    ReportMetadata,
    RiskLevel,
    RiskSummary,
    SecurityCheck,
    VulnerabilitySection,
)
from ports.report_data_builder_port import ReportDataBuilderPort


class SourceReportDataBuilder(ReportDataBuilderPort, ABC):
    """Base for Flutter, React Native, and native source builders."""

    def build(self, post_scan_data: Mapping[str, Any], metadata: ReportMetadata) -> ReportData:
        if metadata.target.target_kind != self.target_kind:
            raise ValueError(f"Flutter report builder requires target_kind={self.target_kind.value}")
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
            cls._check(str(check_name), value) for check_name, value in evidence.items() if isinstance(value, Mapping)
        )
        return VulnerabilitySection(name=name, findings_text="", checks=checks)

    @staticmethod
    def _check(name: str, value: Mapping[str, Any]) -> SecurityCheck:
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
        return SecurityCheck(
            name=name,
            severity=check_severity,
            result=result,
            explanation=str(value.get("explanation") or ""),
            evidence=str(value.get("evidence") or ""),
            compliance=str(value.get("compliance") or ""),
            remediation_link=str(value.get("remediation_link") or ""),
        )

    @staticmethod
    def _risk(section: VulnerabilitySection) -> RiskLevel:
        severities = [c.severity for c in section.checks if c.result == CheckResult.PRESENT]
        return (
            RiskLevel.HIGH
            if any(s in (CheckSeverity.CRITICAL, CheckSeverity.HIGH) for s in severities)
            else RiskLevel.MEDIUM
            if CheckSeverity.MEDIUM in severities
            else RiskLevel.LOW
            if severities
            else RiskLevel.NOT_EVALUATED
        )

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
