"""Build standard report data from React Native source post-scan output."""

from typing import Any, Mapping

from adapters.output.phoenix_report.builders.source import SourceReportDataBuilder
from domain.report import (
    ReactNativePlatformDetails,
    ReactNativeReportDetails,
    ReactNativeRuntimeDetails,
    ReportData,
    ReportMetadata,
    ReportTargetKind,
)


class ReactNativeReportDataBuilder(SourceReportDataBuilder):
    """Apply the standard source report assembly to React Native evidence."""

    @property
    def target_kind(self) -> ReportTargetKind:
        return ReportTargetKind.REACT_NATIVE_SOURCE

    def build(self, post_scan_data: Mapping[str, Any], metadata: ReportMetadata) -> ReportData:
        if metadata.target.target_kind != self.target_kind:
            raise ValueError(f"React Native report builder requires target_kind={self.target_kind.value}")
        return super().build(post_scan_data, metadata)

    def _build_details(self, data: Mapping[str, Any]) -> ReactNativeReportDetails:
        source = data.get("source_metadata") if isinstance(data.get("source_metadata"), Mapping) else {}
        identity = source.get("identity") if isinstance(source.get("identity"), Mapping) else {}
        runtime = source.get("runtime") if isinstance(source.get("runtime"), Mapping) else {}
        platforms = source.get("platforms") if isinstance(source.get("platforms"), Mapping) else {}
        return ReactNativeReportDetails(
            package_name=str(identity.get("package_name") or ""),
            version_name=str(identity.get("version") or ""),
            runtime=ReactNativeRuntimeDetails(
                str(runtime.get("react_native_constraint") or ""), str(runtime.get("expo_constraint") or "")
            ),
            platforms=ReactNativePlatformDetails(platforms.get("android") is True, platforms.get("ios") is True),
        )
