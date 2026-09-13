from typing import Any, Mapping

from adapters.output.phoenix_report.builders.source import SourceReportDataBuilder
from domain.report.models import NativeAndroidReportDetails, ReportTargetKind


class NativeAndroidReportDataBuilder(SourceReportDataBuilder):
    @property
    def target_kind(self) -> ReportTargetKind:
        return ReportTargetKind.NATIVE_ANDROID_SOURCE

    def _build_details(self, data: Mapping[str, Any]) -> NativeAndroidReportDetails:
        app = data.get("app_info") if isinstance(data.get("app_info"), Mapping) else {}
        return NativeAndroidReportDetails(str(app.get("package_name") or ""), str(app.get("version_name") or ""))
