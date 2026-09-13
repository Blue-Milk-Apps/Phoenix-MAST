from typing import Any, Mapping

from adapters.output.phoenix_report.builders.source import SourceReportDataBuilder
from domain.report.models import NativeIOSReportDetails, ReportTargetKind


class NativeIOSReportDataBuilder(SourceReportDataBuilder):
    @property
    def target_kind(self) -> ReportTargetKind:
        return ReportTargetKind.NATIVE_IOS_SOURCE

    def _build_details(self, data: Mapping[str, Any]) -> NativeIOSReportDetails:
        app = data.get("app_info") if isinstance(data.get("app_info"), Mapping) else {}
        schemes = data.get("url_schemes") if isinstance(data.get("url_schemes"), list) else []
        return NativeIOSReportDetails(
            bundle_identifier=str(app.get("bundle_identifier") or app.get("package_name") or ""),
            version_name=str(app.get("version_name") or ""),
            minimum_os=str(app.get("minimum_os") or app.get("min_sdk") or ""),
            url_schemes=tuple(str(item.get("url_name") if isinstance(item, Mapping) else item) for item in schemes),
        )
