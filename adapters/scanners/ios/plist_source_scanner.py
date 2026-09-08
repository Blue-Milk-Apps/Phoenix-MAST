"""iOS plist source scanner adapter."""

from __future__ import annotations

import json
import re
from pathlib import Path

from domain.models import ScanConfig, ScanResult, ScanType
from ports.scanner_port import ScannerPort
from utilities.plist_report import PlistReportBuilder


class PlistSourceScanner(ScannerPort):
    """Scanner for normalizing plist files from source trees."""

    SUPPORTED_SUFFIXES = frozenset({".plist", ".entitlements", ".xcprivacy"})
    XCODE_BUILD_SETTING_PATTERN = re.compile(r"^\s*([A-Za-z0-9_]+)\s*=\s*(.*?)\s*;\s*$", re.MULTILINE)
    XCODE_TARGET_NAME_PATTERN = re.compile(
        r"/\*\s*(.*?)\s*\*/\s*=\s*\{\s*isa\s*=\s*PBXNativeTarget;",
        re.DOTALL,
    )
    XCODE_VARIABLE_PATTERN = re.compile(r"\$\(([^)]+)\)")

    def __init__(self, output_format: str = "json") -> None:
        self._output_format = self._normalize_output_format(output_format)

    @property
    def scan_type(self) -> ScanType:
        return ScanType.PLIST_SOURCE

    @property
    def name(self) -> str:
        return "Plist Source Saver"

    @property
    def description(self) -> str:
        return "Normalized plist files from the source tree written to the scan output directory."

    def is_available(self) -> bool:
        return True

    def scan(self, config: ScanConfig) -> list[ScanResult]:
        plist_files = self._collect_plist_files(config.project_path)
        if not plist_files:
            error_message = "No plist files, entitlements, or privacy manifests found in the source project."
            raw_output = json.dumps(
                {
                    "error": error_message,
                    "skipped": True,
                },
                indent=2,
                sort_keys=True,
            )
            return [
                ScanResult(
                    scanner_name=self.name,
                    scan_type=self.scan_type,
                    success=False,
                    skipped=True,
                    error_message=error_message,
                    raw_output=raw_output,
                    relative_target_path="scan_summary.json",
                )
            ]

        variables = self._xcode_build_variables(config.project_path)
        return PlistReportBuilder(
            scanner_name=self.name,
            scan_type=self.scan_type,
            description=self.description,
            base_path=config.project_path.parent if config.project_path.is_file() else config.project_path,
            output_format=self._output_format,
            plist_transform=lambda data: self._resolve_xcode_variables(data, variables),
        ).build(plist_files)

    def _collect_plist_files(self, project_path: Path) -> list[Path]:
        if project_path.is_file():
            return [project_path] if project_path.suffix.lower() in self.SUPPORTED_SUFFIXES else []
        return sorted(
            path
            for path in project_path.rglob("*")
            if path.is_file() and path.suffix.lower() in self.SUPPORTED_SUFFIXES
        )

    def _xcode_build_variables(self, project_path: Path) -> dict[str, str]:
        root = project_path.parent if project_path.is_file() else project_path
        settings: dict[str, list[str]] = {}
        for project_file in sorted(
            path for path in root.rglob("project.pbxproj") if path.parent.suffix.lower() == ".xcodeproj"
        ):
            try:
                content = project_file.read_text(encoding="utf-8")
            except OSError:
                continue
            for key, raw_value in self.XCODE_BUILD_SETTING_PATTERN.findall(content):
                value = raw_value.strip().strip('"')
                if value and value not in settings.setdefault(key, []):
                    settings[key].append(value)

            target_names = self.XCODE_TARGET_NAME_PATTERN.findall(content)
            for target_name in target_names:
                name = target_name.strip()
                if name and name not in settings.setdefault("TARGET_NAME", []):
                    settings["TARGET_NAME"].append(name)

        return {
            key: next((value for value in values if "$(" not in value), values[0])
            for key, values in settings.items()
            if values
        }

    def _resolve_xcode_variables(self, value: object, variables: dict[str, str]) -> object:
        if isinstance(value, dict):
            return {key: self._resolve_xcode_variables(item, variables) for key, item in value.items()}
        if isinstance(value, list):
            return [self._resolve_xcode_variables(item, variables) for item in value]
        if not isinstance(value, str):
            return value

        def replacement(match: re.Match[str]) -> str:
            name = match.group(1).split(":", 1)[0]
            return variables.get(name, match.group(0))

        resolved = value
        for _ in range(10):
            updated = self.XCODE_VARIABLE_PATTERN.sub(replacement, resolved)
            if updated == resolved:
                break
            resolved = updated
        return resolved

    @staticmethod
    def _normalize_output_format(output_format: str) -> str:
        normalized = output_format.strip().lower()
        if normalized not in {"json", "xml"}:
            raise ValueError("output_format must be 'json' or 'xml'")
        return normalized
