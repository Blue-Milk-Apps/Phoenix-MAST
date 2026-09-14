from typing import Any, Mapping

from adapters.output.phoenix_report.builders.android.source_check_catalog import ANDROID_SOURCE_SECTION_CHECKS
from adapters.output.phoenix_report.builders.source import SourceReportDataBuilder
from domain.report.models import (
    AndroidApplicationDetails,
    AppComponentSummary,
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
    check_sections = ANDROID_SOURCE_SECTION_CHECKS

    @property
    def target_kind(self) -> ReportTargetKind:
        return ReportTargetKind.NATIVE_ANDROID_SOURCE

    def _build_details(self, data: Mapping[str, Any]) -> NativeAndroidReportDetails:
        app = data.get("app_info") if isinstance(data.get("app_info"), Mapping) else {}
        application = data.get("application") if isinstance(data.get("application"), Mapping) else {}
        components = data.get("app_components") if isinstance(data.get("app_components"), Mapping) else {}
        hardcoded = data.get("hardcoded_values") if isinstance(data.get("hardcoded_values"), Mapping) else {}
        functionality = data.get("functionality") if isinstance(data.get("functionality"), Mapping) else {}
        return NativeAndroidReportDetails(
            package_name=str(app.get("package_name") or ""),
            version_name=str(app.get("version_name") or ""),
            target_sdk=str(app.get("target_sdk") or ""),
            min_sdk=str(app.get("min_sdk") or ""),
            application=AndroidApplicationDetails(
                debuggable=self._optional_bool(application.get("debuggable")),
                allow_backup=self._optional_bool(application.get("allow_backup")),
                uses_cleartext_traffic=self._optional_bool(application.get("uses_cleartext_traffic")),
            ),
            app_components=AppComponentSummary(
                activities=self._integer(components.get("activities")),
                services=self._integer(components.get("services")),
                receivers=self._integer(components.get("receivers")),
                providers=self._integer(components.get("providers")),
                exported_activities=self._integer(components.get("exported_activities")),
                exported_services=self._integer(components.get("exported_services")),
                exported_receivers=self._integer(components.get("exported_receivers")),
                exported_providers=self._integer(components.get("exported_providers")),
            ),
            functionality=tuple(
                FunctionalityDetails(
                    name=str(name),
                    present=item.get("present"),
                    explanation=str(item.get("explanation") or "")
                    or self._functionality_explanation(str(name), item.get("present")),
                )
                for name, item in functionality.items()
                if isinstance(item, Mapping)
            ),
            permissions=tuple(
                PermissionDetails(
                    permission=str(item.get("permission") or item.get("name") or ""),
                    status=str(item.get("status") or ""),
                    info=str(item.get("info") or ""),
                    usage_description=str(item.get("usage_description") or ""),
                    general_description=(
                        str(item.get("general_description") or "")
                        or f"The application requests the {str(item.get('permission') or item.get('name') or '')} permission."
                    ),
                )
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

    @staticmethod
    def _optional_bool(value: object) -> bool | None:
        return value if isinstance(value, bool) else None

    @staticmethod
    def _integer(value: object) -> int:
        return value if isinstance(value, int) and not isinstance(value, bool) else 0

    @staticmethod
    def _functionality_explanation(name: str, present: object) -> str:
        if present is True:
            return f"{name} functionality was identified in the available scan evidence."
        if present is False:
            return f"No permission or scan evidence indicated {name} functionality."
        return f"{name} functionality was not evaluated because the required scan evidence is unavailable."
