"""Source report metadata and inventory; rule checks are composed from YAML snapshots."""

from abc import ABC
from typing import Any, Mapping

from domain.report import (
    AssessmentStatus,
    FindingSeverity,
    FunctionalityDetails,
    PlatformAssessment,
    ReportData,
    ReportMetadata,
    ReportPlatform,
)
from ports.report_data_builder_port import ReportDataBuilderPort


class SourceReportDataBuilder(ReportDataBuilderPort, ABC):
    def build(self, post_scan_data: Mapping[str, Any], metadata: ReportMetadata) -> ReportData:
        if metadata.target.target_kind != self.target_kind:
            raise ValueError(f"Source report builder requires target_kind={self.target_kind.value}")
        return ReportData(metadata, (), (), (), FindingSeverity(), self._build_details(post_scan_data))

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
