"""Shared implementation boundary for binary report builders."""

from abc import ABC
from dataclasses import replace

from domain.report import (
    AssessmentStatus,
    FunctionalityDetails,
    PlatformAssessment,
    ReportPlatform,
    SecurityCheck,
    VulnerabilitySection,
)
from ports.report_data_builder_port import ReportDataBuilderPort


class BinaryReportDataBuilder(ReportDataBuilderPort, ABC):
    """Base for Android and iOS binary builders."""

    @staticmethod
    def _single_platform_functionality(
        name: object,
        value: object,
        platform: ReportPlatform,
        explanation: str = "",
    ) -> FunctionalityDetails:
        present = value if isinstance(value, bool) else None
        status = (
            AssessmentStatus.PRESENT
            if present is True
            else AssessmentStatus.NOT_PRESENT
            if present is False
            else AssessmentStatus.NOT_EVALUATED
        )
        explanation = explanation.strip() or BinaryReportDataBuilder._functionality_explanation(str(name), status)
        return FunctionalityDetails(
            name=str(name),
            present=present,
            explanation=explanation,
            platform_assessments=(PlatformAssessment(platform=platform, status=status, explanation=explanation),),
            status=status,
        )

    @staticmethod
    def _functionality_explanation(name: str, status: AssessmentStatus) -> str:
        if status == AssessmentStatus.PRESENT:
            return f"Evidence indicates that {name.lower()} functionality is present."
        if status == AssessmentStatus.NOT_PRESENT:
            return f"No evidence indicates that {name.lower()} functionality is present."
        return "Not evaluated because functionality evidence was not produced by the binary scan."

    @staticmethod
    def _attach_single_platform_assessments(
        sections: tuple[VulnerabilitySection, ...],
        platform: ReportPlatform,
    ) -> tuple[VulnerabilitySection, ...]:
        return tuple(
            replace(
                section,
                checks=tuple(
                    BinaryReportDataBuilder._single_platform_check(check, platform) for check in section.checks
                ),
            )
            for section in sections
        )

    @staticmethod
    def _single_platform_check(check: SecurityCheck, platform: ReportPlatform) -> SecurityCheck:
        status = check.result
        return replace(
            check,
            platform_assessments=(
                PlatformAssessment(
                    platform=platform,
                    status=status,
                    explanation=check.explanation,
                    evidence=(check.evidence,) if check.evidence else (),
                ),
            ),
            status=status,
        )
