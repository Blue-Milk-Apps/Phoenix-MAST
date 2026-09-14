"""Build standard report data from React Native source post-scan output."""

from typing import Any, Mapping

from adapters.output.phoenix_report.builders.react_native.source_check_catalog import REACT_NATIVE_SOURCE_SECTION_CHECKS
from adapters.output.phoenix_report.builders.source import SourceReportDataBuilder
from domain.report import (
    EndpointDetails,
    FlutterDependencyDetails,
    FunctionalityDetails,
    HardcodedSecretDetails,
    HardcodedUrlDetails,
    HardcodedValuesDetails,
    PermissionDetails,
    ReactNativePlatformDetails,
    ReactNativeReportDetails,
    ReactNativeRuntimeDetails,
    ReportData,
    ReportMetadata,
    ReportTargetKind,
)


class ReactNativeReportDataBuilder(SourceReportDataBuilder):
    """Apply the standard source report assembly to React Native evidence."""

    check_sections = REACT_NATIVE_SOURCE_SECTION_CHECKS

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
        dependencies = source.get("dependencies") if isinstance(source.get("dependencies"), Mapping) else {}
        dependency_items = tuple(
            FlutterDependencyDetails(
                name=str(item.get("name") or ""),
                version=str(item.get("version") or ""),
                constraint=str(item.get("constraint") or ""),
                source=str(item.get("source") or ""),
                group=group,
            )
            for group in ("declared", "resolved")
            for item in dependencies.get(group, ())
            if isinstance(item, Mapping) and item.get("name")
        )
        functionality = data.get("functionality") if isinstance(data.get("functionality"), Mapping) else {}
        hardcoded = data.get("hardcoded_values") if isinstance(data.get("hardcoded_values"), Mapping) else {}
        return ReactNativeReportDetails(
            package_name=str(identity.get("package_name") or ""),
            version_name=str(identity.get("version") or ""),
            runtime=ReactNativeRuntimeDetails(
                str(runtime.get("react_native_constraint") or ""), str(runtime.get("expo_constraint") or "")
            ),
            platforms=ReactNativePlatformDetails(platforms.get("android") is True, platforms.get("ios") is True),
            dependencies=dependency_items,
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
