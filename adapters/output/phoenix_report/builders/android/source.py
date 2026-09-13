from typing import Any, Mapping

from adapters.output.phoenix_report.builders.source import SourceReportDataBuilder
from domain.report.models import (
    EndpointDetails,
    FunctionalityDetails,
    HardcodedSecretDetails,
    HardcodedUrlDetails,
    HardcodedValuesDetails,
    NativeAndroidReportDetails,
    PermissionDetails,
    ReportTargetKind,
)


class NativeAndroidReportDataBuilder(SourceReportDataBuilder):
    @property
    def target_kind(self) -> ReportTargetKind:
        return ReportTargetKind.NATIVE_ANDROID_SOURCE

    def _build_details(self, data: Mapping[str, Any]) -> NativeAndroidReportDetails:
        app = data.get("app_info") if isinstance(data.get("app_info"), Mapping) else {}
        hardcoded = data.get("hardcoded_values") if isinstance(data.get("hardcoded_values"), Mapping) else {}
        functionality = data.get("functionality") if isinstance(data.get("functionality"), Mapping) else {}
        return NativeAndroidReportDetails(
            package_name=str(app.get("package_name") or ""),
            version_name=str(app.get("version_name") or ""),
            target_sdk=str(app.get("target_sdk") or ""),
            min_sdk=str(app.get("min_sdk") or ""),
            functionality=tuple(
                FunctionalityDetails(str(name), item.get("present"), str(item.get("explanation") or ""))
                for name, item in functionality.items()
                if isinstance(item, Mapping)
            ),
            permissions=tuple(
                PermissionDetails(str(item.get("permission") or item.get("name") or ""), str(item.get("status") or ""))
                for item in data.get("permissions", ())
                if isinstance(item, Mapping)
            ),
            hardcoded_values=HardcodedValuesDetails(
                urls=tuple(
                    HardcodedUrlDetails(str(item.get("url") or ""), str(item.get("country") or ""))
                    for item in hardcoded.get("urls", ())
                    if isinstance(item, Mapping)
                ),
                emails=tuple(str(item) for item in hardcoded.get("emails", ()) if str(item).strip()),
                secrets=tuple(
                    HardcodedSecretDetails(str(item.get("value") or item))
                    for item in hardcoded.get("secrets", ())
                    if str(item).strip()
                ),
            ),
            endpoints=tuple(
                EndpointDetails(str(item.get("endpoint") or ""), country=str(item.get("country") or ""))
                for item in data.get("endpoints", ())
                if isinstance(item, Mapping)
            ),
        )
