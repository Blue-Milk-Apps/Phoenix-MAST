"""Build React Native source project file information."""

from __future__ import annotations

from dataclasses import dataclass

from domain.post_scan.react_native.scan_extraction_context import ReactNativeScanExtractionContext


@dataclass
class ReactNativeFileInfo:
    filename: str
    size: str
    md5: str
    sha1: str
    sha256: str
    package_json_path: str
    app_json_path: str
    lockfiles: list[str]
    package_manager: str

    def __init__(self, context: ReactNativeScanExtractionContext) -> None:
        project = context.project
        self.filename = context.project_path.name
        self.size = ""
        self.md5 = ""
        self.sha1 = ""
        self.sha256 = ""
        self.package_json_path = context.first_non_empty(project.get("package_json_path"))
        self.app_json_path = context.first_non_empty(project.get("app_json_path"))
        self.lockfiles = context.string_list(project.get("lockfiles"))
        self.package_manager = context.first_non_empty(project.get("package_manager"))
