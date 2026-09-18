from typing import Any, Mapping

from adapters.output.phoenix_report.builders.ios.source_check_catalog import IOS_SOURCE_SECTION_CHECKS
from adapters.output.phoenix_report.builders.source import SourceReportDataBuilder
from domain.report.models import (
    EndpointDetails,
    HardcodedSecretDetails,
    HardcodedUrlDetails,
    HardcodedValuesDetails,
    NativeIOSReportDetails,
    PermissionDetails,
    ReportPlatform,
    ReportTargetKind,
)


class NativeIOSReportDataBuilder(SourceReportDataBuilder):
    check_sections = IOS_SOURCE_SECTION_CHECKS
    _excluded_functionalities = frozenset({"fingerprint", "google cloud messaging", "infrared led"})

    @property
    def target_kind(self) -> ReportTargetKind:
        return ReportTargetKind.NATIVE_IOS_SOURCE

    def _build_details(self, data: Mapping[str, Any]) -> NativeIOSReportDetails:
        app = data.get("app_info") if isinstance(data.get("app_info"), Mapping) else {}
        schemes = data.get("url_schemes") if isinstance(data.get("url_schemes"), list) else []
        functionality = data.get("functionality") if isinstance(data.get("functionality"), Mapping) else {}
        hardcoded = data.get("hardcoded_values") if isinstance(data.get("hardcoded_values"), Mapping) else {}
        return NativeIOSReportDetails(
            bundle_identifier=str(app.get("bundle_identifier") or app.get("package_name") or ""),
            version_name=str(app.get("version_name") or ""),
            minimum_os=str(app.get("minimum_os") or app.get("min_sdk") or ""),
            url_schemes=tuple(str(item.get("url_name") if isinstance(item, Mapping) else item) for item in schemes),
            functionality=tuple(
                self._single_platform_functionality(
                    name,
                    {
                        **item,
                        "explanation": str(item.get("explanation") or "")
                        or (
                            f"{name} functionality was identified in the available scan evidence."
                            if item.get("present") is True
                            else f"No permission or scan evidence indicated {name} functionality."
                        ),
                    },
                    ReportPlatform.IOS,
                )
                for name, item in functionality.items()
                if isinstance(item, Mapping)
                and str(name).strip().casefold() not in NativeIOSReportDataBuilder._excluded_functionalities
            ),
            permissions=tuple(
                NativeIOSReportDataBuilder._permission_details(item)
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
            third_party_sdks=tuple(
                str(name)
                for name in data.get("third_party_sdks", {})
                if isinstance(data.get("third_party_sdks"), Mapping)
            ),
        )

    @staticmethod
    def _permission_details(item: Mapping[str, Any]) -> PermissionDetails:
        permission = str(item.get("permission") or item.get("name") or "")
        return PermissionDetails(
            permission=permission,
            status=str(item.get("status") or ""),
            info=str(item.get("info") or ""),
            usage_description=str(item.get("usage_description") or ""),
            general_description=(
                str(item.get("general_description") or "") or f"The application requests the {permission} permission."
            ),
        )
