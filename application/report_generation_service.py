"""Build standard report data from persisted post-scan output."""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any, Mapping

from domain.report import (
    ReportData,
    ReportMetadata,
    ReportPlatform,
    ReportStack,
    ReportTarget,
    ReportTargetKind,
    ReportTargetType,
)
from ports.report_data_builder_port import ReportDataBuilderPort


class ReportDataBuilderResolver:
    """Select a registered builder for a canonical report target."""

    def __init__(self, builders: Iterable[ReportDataBuilderPort]) -> None:
        self._builders = {builder.target_kind: builder for builder in builders}

    def resolve(self, target_kind: ReportTargetKind) -> ReportDataBuilderPort:
        """Return the builder registered for the target kind."""

        try:
            return self._builders[target_kind]
        except KeyError as error:
            raise ValueError(f"No report data builder is registered for {target_kind.value}") from error


class ReportGenerationService:
    """Create format-independent report data from persisted scan output."""

    def __init__(self, builders: Iterable[ReportDataBuilderPort]) -> None:
        self._builder_resolver = ReportDataBuilderResolver(builders)

    def build_report_data(self, post_scan_data: Mapping[str, Any]) -> ReportData:
        """Build report data using the target information stored with a scan."""

        metadata = self._metadata_from(post_scan_data)
        builder = self._builder_resolver.resolve(metadata.target.target_kind)
        return builder.build(post_scan_data, metadata)

    @classmethod
    def _metadata_from(cls, post_scan_data: Mapping[str, Any]) -> ReportMetadata:
        target_information = cls._mapping(post_scan_data, "target_information")
        target = ReportTarget(
            target_kind=ReportTargetKind(cls._required_text(target_information, "target_kind")),
            platform=ReportPlatform(cls._required_text(target_information, "platform")),
            target_type=ReportTargetType(cls._required_text(target_information, "target_type")),
            stack=cls._stack(target_information),
        )
        meta = cls._mapping(post_scan_data, "meta")
        app_info = cls._mapping(post_scan_data, "app_info")
        file_info = cls._mapping(post_scan_data, "file_info")
        return ReportMetadata(
            target=target,
            app_display_name=cls._text(meta, "app_display_name") or cls._text(app_info, "name"),
            file_name=cls._text(meta, "file_name") or cls._text(file_info, "filename"),
            package_name=cls._text(meta, "package_name") or cls._text(app_info, "package_name"),
            scan_date=cls._text(meta, "scan_date"),
            version_name=cls._text(meta, "version_name") or cls._text(app_info, "version_name"),
            version_code=cls._text(meta, "version_code"),
            reviewer_org=cls._text(meta, "reviewer_org"),
        )

    @staticmethod
    def _mapping(data: Mapping[str, Any], key: str) -> Mapping[str, Any]:
        value = data.get(key)
        return value if isinstance(value, Mapping) else {}

    @staticmethod
    def _required_text(data: Mapping[str, Any], key: str) -> str:
        value = str(data.get(key) or "").strip()
        if not value:
            raise ValueError(f"Persisted target_information is missing {key}")
        return value

    @classmethod
    def _stack(cls, target_information: Mapping[str, Any]) -> ReportStack | None:
        value = cls._text(target_information, "stack")
        return ReportStack(value) if value else None

    @staticmethod
    def _text(data: Mapping[str, Any], key: str) -> str:
        return str(data.get(key) or "").strip()
