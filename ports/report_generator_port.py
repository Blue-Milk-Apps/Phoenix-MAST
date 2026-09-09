"""Report generation port."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Protocol


class ReportGeneratorPort(Protocol):
    """Generate a report from post-scan data."""

    def generate(
        self,
        input_data: dict[str, Any] | Path | str,
        output_path: Path | str,
        *,
        show_confidence_caveats: bool = False,
    ) -> Path: ...
