"""Static metadata extraction for Flutter source projects."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import yaml

from domain.models import ScanConfig, ScanResult, ScanType
from ports.scanner_port import ScannerPort


class FlutterSourceMetadataScanner(ScannerPort):
    """Normalize Flutter pubspec metadata without executing project code."""

    SCHEMA_VERSION = "1.0"
    REPORT_PATH = "project_metadata.json"
    PLATFORM_DIRECTORIES = ("android", "ios", "web", "linux", "macos", "windows")

    @property
    def scan_type(self) -> ScanType:
        return ScanType.FLUTTER_SOURCE_METADATA

    @property
    def name(self) -> str:
        return "Flutter Source Metadata Scanner"

    @property
    def description(self) -> str:
        return "Static Flutter project, SDK, platform, and declared-dependency metadata extraction."

    def is_available(self) -> bool:
        return True

    def scan(self, config: ScanConfig) -> list[ScanResult]:
        project_path = config.project_path.resolve()
        if not project_path.is_dir():
            return [self._failure(f"Flutter source target is not a directory: {project_path}")]

        pubspec_path = project_path / "pubspec.yaml"
        if not pubspec_path.is_file():
            return [self._failure("No pubspec.yaml file found at the Flutter project root.", skipped=True)]

        try:
            pubspec = yaml.safe_load(pubspec_path.read_text(encoding="utf-8"))
        except (OSError, yaml.YAMLError) as exc:
            return [self._failure(f"Unable to parse {pubspec_path}: {exc}")]

        if not isinstance(pubspec, dict):
            return [self._failure(f"Flutter pubspec must contain a YAML mapping: {pubspec_path}")]

        payload = self._metadata_payload(project_path, pubspec_path, pubspec)
        return [
            ScanResult(
                scanner_name=self.name,
                scan_type=self.scan_type,
                success=True,
                raw_output=json.dumps(payload, indent=2, sort_keys=True),
                relative_target_path=self.REPORT_PATH,
                description=self.description,
            )
        ]

    def _metadata_payload(
        self,
        project_path: Path,
        pubspec_path: Path,
        pubspec: dict[str, Any],
    ) -> dict[str, Any]:
        lock_path = project_path / "pubspec.lock"
        warnings = (
            [] if lock_path.is_file() else ["No pubspec.lock file found; resolved dependencies were not assessed."]
        )
        version, version_name, version_code = self._version_parts(pubspec.get("version"))
        environment = self._mapping(pubspec.get("environment"))

        return {
            "schema_version": self.SCHEMA_VERSION,
            "extraction": {
                "status": "partial" if warnings else "complete",
                "warnings": warnings,
            },
            "project": {
                "project_path": str(project_path),
                "pubspec_path": pubspec_path.relative_to(project_path).as_posix(),
                "pubspec_lock_path": lock_path.relative_to(project_path).as_posix() if lock_path.is_file() else "",
            },
            "identity": {
                "package_name": self._text(pubspec.get("name")),
                "description": self._text(pubspec.get("description")),
                "version": version,
                "version_name": version_name,
                "version_code": version_code,
                "publish_to": self._text(pubspec.get("publish_to")),
                "homepage": self._text(pubspec.get("homepage")),
                "repository": self._text(pubspec.get("repository")),
            },
            "sdk": {
                "dart_constraint": self._text(environment.get("sdk")),
                "flutter_constraint": self._text(environment.get("flutter")),
            },
            "platforms": {platform: (project_path / platform).is_dir() for platform in self.PLATFORM_DIRECTORIES},
            "dependencies": {
                "direct": self._declared_dependencies(pubspec.get("dependencies")),
                "development": self._declared_dependencies(pubspec.get("dev_dependencies")),
                "resolved": [],
            },
        }

    def _declared_dependencies(self, value: object) -> list[dict[str, str]]:
        dependencies = self._mapping(value)
        return [self._declared_dependency(str(name), declaration) for name, declaration in sorted(dependencies.items())]

    def _declared_dependency(self, name: str, declaration: object) -> dict[str, str]:
        if isinstance(declaration, str):
            return {"name": name, "constraint": declaration.strip(), "source": "hosted"}
        if not isinstance(declaration, dict):
            return {"name": name, "constraint": self._text(declaration), "source": "unknown"}

        source = next(
            (candidate for candidate in ("sdk", "git", "path", "hosted") if candidate in declaration),
            "hosted",
        )
        constraint = self._text(declaration.get("version"))
        if source == "sdk" and not constraint:
            constraint = self._text(declaration.get("sdk"))
        return {"name": name, "constraint": constraint, "source": source}

    @staticmethod
    def _version_parts(value: object) -> tuple[str, str, str]:
        version = FlutterSourceMetadataScanner._text(value)
        if "+" not in version:
            return version, version, ""
        version_name, version_code = version.rsplit("+", 1)
        return version, version_name.strip(), version_code.strip()

    @staticmethod
    def _mapping(value: object) -> dict[str, Any]:
        return value if isinstance(value, dict) else {}

    @staticmethod
    def _text(value: object) -> str:
        return str(value).strip() if value is not None else ""

    def _failure(self, error_message: str, *, skipped: bool = False) -> ScanResult:
        return ScanResult(
            scanner_name=self.name,
            scan_type=self.scan_type,
            success=False,
            skipped=skipped,
            error_message=error_message,
            raw_output=json.dumps(
                {"error": error_message, "skipped": skipped, "success": False},
                indent=2,
                sort_keys=True,
            ),
            relative_target_path="scan_summary.json",
            description=self.description,
        )
