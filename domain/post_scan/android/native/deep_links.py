"""Build native Android source deep-link details."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from domain.post_scan.android.native.scan_extraction_context import NativeAndroidScanExtractionContext


@dataclass
class NativeAndroidDeepLinks:
    deep_links: list[dict[str, Any]] | None

    def __init__(self, context: NativeAndroidScanExtractionContext) -> None:
        value = context.source_metadata.get("deep_links")
        self.deep_links = context.deep_links if isinstance(value, list) else None
