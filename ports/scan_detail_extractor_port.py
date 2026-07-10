"""Port for extracting report sections from loaded scan outputs."""

from __future__ import annotations

from typing import Any, Protocol


class ScanDetailExtractorPort(Protocol):
    """Extract report sections from loaded scan outputs."""

    def extract_sections(self, loaded_outputs: dict[str, Any]) -> dict[str, Any]:
        """Return report sections other than the shared/common ones."""
