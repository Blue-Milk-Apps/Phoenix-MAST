"""Build standard report data from React Native source post-scan output."""

from typing import Any, Mapping

from adapters.output.phoenix_report.builders.source import SourceReportDataBuilder
from domain.report import ReportData, ReportMetadata, ReportTargetKind


class ReactNativeReportDataBuilder(SourceReportDataBuilder):
    """Apply the standard source report assembly to React Native evidence."""

    @property
    def target_kind(self) -> ReportTargetKind:
        return ReportTargetKind.REACT_NATIVE_SOURCE

    def build(self, post_scan_data: Mapping[str, Any], metadata: ReportMetadata) -> ReportData:
        if metadata.target.target_kind != self.target_kind:
            raise ValueError(f"React Native report builder requires target_kind={self.target_kind.value}")
        return super().build(post_scan_data, metadata)
