"""Build native Android source project file information."""

from __future__ import annotations

from dataclasses import dataclass

from domain.post_scan.android.native.scan_extraction_context import NativeAndroidScanExtractionContext


@dataclass
class NativeAndroidFileInfo:
    filename: str
    size: str
    md5: str
    sha1: str
    sha256: str

    def __init__(self, context: NativeAndroidScanExtractionContext) -> None:
        self.filename = context.project_path.name
        self.size = ""
        self.md5 = ""
        self.sha1 = ""
        self.sha256 = ""
