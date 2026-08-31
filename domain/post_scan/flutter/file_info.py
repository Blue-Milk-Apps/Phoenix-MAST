"""Build Flutter source project file information."""

from __future__ import annotations

from dataclasses import dataclass

from domain.post_scan.flutter.scan_extraction_context import FlutterScanExtractionContext


@dataclass
class FlutterFileInfo:
    filename: str
    size: str
    md5: str
    sha1: str
    sha256: str
    pubspec_path: str
    pubspec_lock_path: str

    def __init__(self, context: FlutterScanExtractionContext) -> None:
        self.filename = context.project_path.name
        self.size = ""
        self.md5 = ""
        self.sha1 = ""
        self.sha256 = ""
        self.pubspec_path = context.first_non_empty(context.project.get("pubspec_path"))
        self.pubspec_lock_path = context.first_non_empty(context.project.get("pubspec_lock_path"))
