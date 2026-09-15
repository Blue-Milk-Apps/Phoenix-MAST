"""Report generation port."""

from __future__ import annotations

from pathlib import Path
from typing import Protocol

from domain.report import ReportData


class ReportGeneratorPort(Protocol):
    """Generate a report from standard report data."""

    def generate(
        self,
        input_data: ReportData,
        output_path: Path | str,
        *,
        show_confidence_caveats: bool = False,
    ) -> Path: ...
