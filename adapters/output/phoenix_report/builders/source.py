"""Shared implementation boundary for source report builders."""

from abc import ABC

from ports.report_data_builder_port import ReportDataBuilderPort


class SourceReportDataBuilder(ReportDataBuilderPort, ABC):
    """Base for Flutter, React Native, and native source builders."""
