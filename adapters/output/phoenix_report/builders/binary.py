"""Shared implementation boundary for binary report builders."""

from abc import ABC

from ports.report_data_builder_port import ReportDataBuilderPort


class BinaryReportDataBuilder(ReportDataBuilderPort, ABC):
    """Base for Android and iOS binary builders."""
