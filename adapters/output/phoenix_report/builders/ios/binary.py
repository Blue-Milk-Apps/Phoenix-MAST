"""Build standard report data from iOS binary post-scan output."""

from __future__ import annotations

from typing import Any, Mapping

from adapters.output.phoenix_report.builders.ios.binary_check_catalog import (
    CODE_CHECKS,
    IOSBinaryCheckDefinition,
)
from domain.report import (
    CheckResult,
    ReportData,
    ReportMetadata,
    ReportTargetKind,
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
        raise NotImplementedError("iOS binary report construction requires the remaining canonical sections.")

    @classmethod
    def _code_section(cls, post_scan_data: Mapping[str, Any]) -> VulnerabilitySection:
        code_evidence = cls._mapping(post_scan_data, "code_evidence")
        return VulnerabilitySection(
            name="code",
            findings_text="",
            checks=tuple(cls._code_check(definition, code_evidence) for definition in CODE_CHECKS),
        )

    @classmethod
    def _code_check(
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
