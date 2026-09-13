"""Build standard report data from Flutter source post-scan output."""

from typing import Any, Mapping

from adapters.output.phoenix_report.builders.source import SourceReportDataBuilder
from domain.report import (
    CheckResult,
    CheckSeverity,
    EndpointDetails,
    FindingSeverity,
    FlutterDependencyDetails,
    FlutterReportDetails,
    FunctionalityDetails,
    HardcodedSecretDetails,
    HardcodedUrlDetails,
    HardcodedValuesDetails,
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


class FlutterReportDataBuilder(SourceReportDataBuilder):
    @property
    def target_kind(self) -> ReportTargetKind:
        return ReportTargetKind.FLUTTER_SOURCE

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
            self._details(post_scan_data),
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

    @staticmethod
    def _details(data: Mapping[str, Any]) -> FlutterReportDetails:
        identity = data.get("identity") if isinstance(data.get("identity"), Mapping) else {}
        sdk = data.get("sdk") if isinstance(data.get("sdk"), Mapping) else {}
        platforms = data.get("platforms") if isinstance(data.get("platforms"), Mapping) else {}
        dependencies = data.get("dependency_inventory") if isinstance(data.get("dependency_inventory"), Mapping) else {}
        dependency_items = tuple(
            FlutterDependencyDetails(
                name=str(item.get("name") or ""),
                version=str(item.get("version") or ""),
                constraint=str(item.get("constraint") or ""),
                source=str(item.get("source") or ""),
                group=group,
            )
            for group in ("declared", "development", "resolved")
            for item in dependencies.get(group, ())
            if isinstance(item, Mapping) and item.get("name")
        )
        return FlutterReportDetails(
            package_name=str(identity.get("package_name") or ""),
            version_name=str(identity.get("version_name") or ""),
            dart_constraint=str(sdk.get("dart_constraint") or ""),
            flutter_constraint=str(sdk.get("flutter_constraint") or ""),
            supported_platforms=tuple(str(name) for name, enabled in platforms.items() if enabled is True),
            dependencies=dependency_items,
            functionality=tuple(
                FunctionalityDetails(str(name), value.get("present"), str(value.get("explanation") or ""))
                for name, value in FlutterReportDataBuilder._mapping(data, "functionality").items()
                if isinstance(value, Mapping)
            ),
            permissions=tuple(
                PermissionDetails(
                    permission=str(item.get("permission") or item.get("name") or ""),
                    status=str(item.get("status") or ""),
                    info=str(item.get("info") or ""),
                    usage_description=str(item.get("usage_description") or ""),
                    general_description=str(item.get("general_description") or ""),
                )
                for item in data.get("permissions", ())
                if isinstance(item, Mapping)
            ),
            hardcoded_values=FlutterReportDataBuilder._hardcoded_values(data),
            endpoints=tuple(
                EndpointDetails(
                    endpoint=str(item.get("endpoint") or ""),
                    tags=str(item.get("tags") or ""),
                    ip_address=str(item.get("ip_address") or ""),
                    country=str(item.get("country") or ""),
                )
                for item in data.get("endpoints", ())
                if isinstance(item, Mapping)
            ),
        )

    @staticmethod
    def _hardcoded_values(data: Mapping[str, Any]) -> HardcodedValuesDetails:
        values = data.get("hardcoded_values") if isinstance(data.get("hardcoded_values"), Mapping) else {}
        return HardcodedValuesDetails(
            urls=tuple(
                HardcodedUrlDetails(str(item.get("url") or ""), str(item.get("country") or ""))
                for item in values.get("urls", ())
                if isinstance(item, Mapping)
            ),
            emails=tuple(str(item) for item in values.get("emails", ()) if str(item).strip()),
            secrets=tuple(
                HardcodedSecretDetails(str(item.get("value") or item))
                for item in values.get("secrets", ())
                if str(item).strip()
            ),
        )

    @staticmethod
    def _mapping(data: Mapping[str, Any], key: str) -> Mapping[str, Any]:
        value = data.get(key)
        return value if isinstance(value, Mapping) else {}
