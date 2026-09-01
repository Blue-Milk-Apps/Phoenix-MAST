"""Static metadata extraction for React Native source projects."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from domain.models import ScanConfig, ScanResult, ScanType
from ports.scanner_port import ScannerPort


class ReactNativeMetadataScanner(ScannerPort):
    """Normalize React Native project metadata without executing project code."""

    SCHEMA_VERSION = "1.0"
    REPORT_PATH = "project_metadata.json"

    @property
    def scan_type(self) -> ScanType:
        return ScanType.REACT_NATIVE_METADATA

    @property
    def name(self) -> str:
        return "React Native Metadata Scanner"

    @property
    def description(self) -> str:
        return "Static React Native project, framework, platform, and declared-dependency metadata extraction."

    def is_available(self) -> bool:
        return True

    def scan(self, config: ScanConfig) -> list[ScanResult]:
        project_path = config.project_path.resolve()
        if not project_path.is_dir():
            return [self._failure(f"React Native source target is not a directory: {project_path}")]

        package_json_path = project_path / "package.json"
        if not package_json_path.is_file():
            return [self._failure("No package.json file found at the React Native project root.", skipped=True)]

        try:
            package_json = self._load_json_mapping(package_json_path)
        except (OSError, json.JSONDecodeError) as exc:
            return [self._failure(f"Unable to parse {package_json_path}: {exc}")]

        if package_json is None:
            return [self._failure(f"React Native package.json must contain a JSON mapping: {package_json_path}")]

        app_json_path = project_path / "app.json"
        app_json, warnings = self._optional_json_mapping(app_json_path)
        if not self._is_react_native_project(package_json, app_json):
            return [
                self._failure(
                    "package.json does not declare react-native or expo, and no static Expo configuration was found.",
                    skipped=True,
                )
            ]

        identity = self._identity(package_json, app_json)
        payload = {
            "schema_version": self.SCHEMA_VERSION,
            "extraction": {
                "status": "partial" if warnings else "complete",
                "warnings": warnings,
            },
            "project": {
                "project_path": str(project_path),
                "package_json_path": package_json_path.relative_to(project_path).as_posix(),
                "app_json_path": app_json_path.relative_to(project_path).as_posix() if app_json_path.is_file() else "",
            },
            "identity": identity,
            "framework": self._framework(package_json, project_path),
            "engines": self._engines(package_json),
        }
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

    @staticmethod
    def _load_json_mapping(path: Path) -> dict[str, Any] | None:
        value = json.loads(path.read_text(encoding="utf-8"))
        return value if isinstance(value, dict) else None

    @classmethod
    def _optional_json_mapping(cls, path: Path) -> tuple[dict[str, Any], list[str]]:
        if not path.is_file():
            return {}, []
        try:
            value = cls._load_json_mapping(path)
        except (OSError, json.JSONDecodeError) as exc:
            return {}, [f"Unable to parse {path.name}; application identity may be incomplete: {exc}"]
        if value is None:
            return {}, [f"{path.name} must contain a JSON mapping; application identity may be incomplete."]
        return value, []

    @classmethod
    def _is_react_native_project(
        cls,
        package_json: dict[str, Any],
        app_json: dict[str, Any],
    ) -> bool:
        dependencies = cls._declared_packages(package_json)
        return bool({"expo", "react-native"}.intersection(dependencies)) or isinstance(app_json.get("expo"), dict)

    @classmethod
    def _identity(
        cls,
        package_json: dict[str, Any],
        app_json: dict[str, Any],
    ) -> dict[str, object]:
        expo = cls._mapping(app_json.get("expo"))
        package_name = cls._text(package_json.get("name"))
        app_name = cls._first_non_empty(
            app_json.get("name"),
            expo.get("name"),
            package_name,
        )
        return {
            "package_name": package_name,
            "app_name": app_name,
            "display_name": cls._first_non_empty(
                app_json.get("displayName"),
                expo.get("name"),
                app_name,
            ),
            "slug": cls._text(expo.get("slug")),
            "description": cls._text(package_json.get("description")),
            "version": cls._first_non_empty(package_json.get("version"), expo.get("version")),
            "private": package_json.get("private") is True,
        }

    @classmethod
    def _framework(
        cls,
        package_json: dict[str, Any],
        project_path: Path,
    ) -> dict[str, object]:
        packages = cls._declared_packages(package_json)
        return {
            "react_native_version": cls._text(packages.get("react-native")),
            "react_version": cls._text(packages.get("react")),
            "expo_version": cls._text(packages.get("expo")),
            "typescript": cls._uses_typescript(project_path, packages),
        }

    @classmethod
    def _engines(cls, package_json: dict[str, Any]) -> dict[str, str]:
        engines = cls._mapping(package_json.get("engines"))
        return {name: cls._text(engines.get(name)) for name in ("node", "npm", "yarn", "pnpm")}

    @classmethod
    def _declared_packages(cls, package_json: dict[str, Any]) -> dict[str, Any]:
        return {
            **cls._mapping(package_json.get("devDependencies")),
            **cls._mapping(package_json.get("dependencies")),
        }

    @staticmethod
    def _uses_typescript(project_path: Path, packages: dict[str, Any]) -> bool:
        if (project_path / "tsconfig.json").is_file() or "typescript" in packages:
            return True
        return any((project_path / file_name).is_file() for file_name in ("index.ts", "index.tsx", "App.ts", "App.tsx"))

    @classmethod
    def _first_non_empty(cls, *values: object) -> str:
        return next((text for value in values if (text := cls._text(value))), "")

    @staticmethod
    def _mapping(value: object) -> dict[str, Any]:
        return value if isinstance(value, dict) else {}

    @staticmethod
    def _text(value: object) -> str:
        return str(value).strip() if isinstance(value, str) else ""

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
