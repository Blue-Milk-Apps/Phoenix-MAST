"""Port for loading persisted scan outputs for post-scan processing."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Protocol


class ScanOutputLoaderPort(Protocol):
    """Load persisted scan outputs from a scan result directory."""

    def load(self, scan_output_path: Path) -> dict[str, Any]:
        """Return loaded scan outputs keyed for post-scan processing."""
