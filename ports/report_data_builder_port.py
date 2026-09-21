"""Port for platform-specific report data builders."""

from __future__ import annotations

from typing import Any, Mapping, Protocol

from domain.report import ReportData, ReportMetadata, ReportTargetKind


class ReportDataBuilderPort(Protocol):
    """Build standard report data for one supported target kind."""

    @property
    def target_kind(self) -> ReportTargetKind: ...

    def build(
        self,
        post_scan_data: Mapping[str, Any],
        metadata: ReportMetadata,
    ) -> ReportData: ...
