"""Static metadata extraction for React Native source projects."""

from __future__ import annotations

import json
import re
from dataclasses import replace
from pathlib import Path
from typing import Any

from adapters.scanners.android import NativeAndroidSourceMetadataScanner
from domain.models import ScanConfig, ScanResult, ScanType
from ports.scanner_port import ScannerPort


class ReactNativeMetadataScanner(ScannerPort):
    """Normalize React Native project metadata without executing project code."""

    SCHEMA_VERSION = "1.0"
    REPORT_PATH = "project_metadata.json"
    LOCKFILE_PACKAGE_MANAGERS = (
        ("pnpm-lock.yaml", "pnpm"),
        ("yarn.lock", "yarn"),
        ("package-lock.json", "npm"),
    )

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
        entrypoints = self._entrypoints(package_json, project_path)
        package_manager, lockfiles, package_manager_warnings = self._package_manager_metadata(
            package_json,
            project_path,
        )
        warnings.extend(package_manager_warnings)
        android, android_warnings = self._android_metadata(config, project_path)
        warnings.extend(android_warnings)
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
                "lockfiles": lockfiles,
                "package_manager": package_manager,
            },
            "identity": identity,
            "framework": self._framework(package_json, project_path, entrypoints),
            "engines": self._engines(package_json),
            "platforms": {
                "android": (project_path / "android").is_dir(),
                "ios": (project_path / "ios").is_dir(),
            },
            "entrypoints": entrypoints,
            "dependencies": {
                "direct": self._declared_dependencies(package_json.get("dependencies")),
                "development": self._declared_dependencies(package_json.get("devDependencies")),
            },
            "android": android,
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
        entrypoints: dict[str, object],
    ) -> dict[str, object]:
        packages = cls._declared_packages(package_json)
        return {
            "react_native_version": cls._text(packages.get("react-native")),
            "react_version": cls._text(packages.get("react")),
            "expo_version": cls._text(packages.get("expo")),
            "typescript": cls._uses_typescript(project_path, packages, entrypoints),
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

    @classmethod
    def _declared_dependencies(cls, value: object) -> list[dict[str, str]]:
        dependencies = cls._mapping(value)
        return [
            {
                "name": str(name),
                "constraint": cls._text(constraint),
                "source": cls._dependency_source(constraint),
            }
            for name, constraint in sorted(dependencies.items(), key=lambda item: str(item[0]))
        ]

    @classmethod
    def _dependency_source(cls, value: object) -> str:
        constraint = cls._text(value)
        if not constraint:
            return "unknown"

        lowered = constraint.lower()
        if lowered.startswith("workspace:"):
            return "workspace"
        if lowered.startswith(("file:", "link:", "./", "../", "/")):
            return "path"
        if (
            lowered.startswith(("git+", "git://", "git@", "ssh://", "github:", "gitlab:", "bitbucket:"))
            or re.search(r"\.git(?:#\S*)?$", lowered) is not None
            or re.fullmatch(r"[^/@\s]+/[^/\s]+(?:#\S+)?", constraint) is not None
        ):
            return "git"
        if lowered.startswith(("http://", "https://")):
            return "url"
        return "registry"

    @classmethod
    def _package_manager_metadata(
        cls,
        package_json: dict[str, Any],
        project_path: Path,
    ) -> tuple[str, list[str], list[str]]:
        detected = [
            (lockfile, package_manager)
            for lockfile, package_manager in cls.LOCKFILE_PACKAGE_MANAGERS
            if (project_path / lockfile).is_file()
        ]
        lockfiles = [lockfile for lockfile, _package_manager in detected]
        warnings: list[str] = []
        if len(detected) > 1:
            warnings.append("Multiple package-manager lockfiles found: " + ", ".join(lockfiles) + ".")

        declared_spec = cls._text(package_json.get("packageManager"))
        declared_manager = cls._package_manager_from_spec(declared_spec)
        if declared_spec and not declared_manager:
            warnings.append(f"Unsupported packageManager declaration: {declared_spec}.")

        lockfile_manager = detected[0][1] if detected else ""
        detected_managers = {package_manager for _lockfile, package_manager in detected}
        if declared_manager and detected_managers and declared_manager not in detected_managers:
            warnings.append(
                f"packageManager declares {declared_manager}, but the selected lockfile belongs to {lockfile_manager}."
            )
        return declared_manager or lockfile_manager, lockfiles, warnings

    @staticmethod
    def _package_manager_from_spec(value: str) -> str:
        if not value:
            return ""
        package_manager = value.split("@", 1)[0].strip().lower()
        return package_manager if package_manager in {"npm", "pnpm", "yarn"} else ""

    @classmethod
    def _android_metadata(
        cls,
        config: ScanConfig,
        project_path: Path,
    ) -> tuple[dict[str, object], list[str]]:
        android_path = project_path / "android"
        if not android_path.is_dir():
            return {"available": False, "project_path": "", "metadata": None}, []

        android_config = replace(config, project_path=android_path)
        results = NativeAndroidSourceMetadataScanner().scan(android_config)
        if not results:
            return (
                {"available": True, "project_path": "android", "metadata": None},
                ["Android metadata: Metadata extraction returned no result."],
            )

        result = results[0]
        if not result.success:
            reason = result.error_message or "Android source metadata extraction did not complete."
            return (
                {"available": True, "project_path": "android", "metadata": None},
                [f"Android metadata: {reason}"],
            )

        try:
            metadata = json.loads(result.raw_output)
        except json.JSONDecodeError as exc:
            return (
                {"available": True, "project_path": "android", "metadata": None},
                [f"Android metadata output was not valid JSON: {exc}"],
            )
        if not isinstance(metadata, dict):
            return (
                {"available": True, "project_path": "android", "metadata": None},
                ["Android metadata output was not a JSON mapping."],
            )

        extraction = cls._mapping(metadata.get("extraction"))
        nested_warnings = extraction.get("warnings")
        warnings = (
            [f"Android metadata: {cls._text(item)}" for item in nested_warnings if cls._text(item)]
            if isinstance(nested_warnings, list)
            else []
        )
        return {"available": True, "project_path": "android", "metadata": metadata}, warnings

    @classmethod
    def _entrypoints(cls, package_json: dict[str, Any], project_path: Path) -> dict[str, object]:
        package_main = cls._existing_relative_file(project_path, package_json.get("main"))
        files = [
            relative_path
            for file_name in (
                "index.js",
                "index.jsx",
                "index.ts",
                "index.tsx",
                "App.js",
                "App.jsx",
                "App.ts",
                "App.tsx",
            )
            if (relative_path := cls._existing_relative_file(project_path, file_name))
        ]
        if package_main and package_main not in files:
            files.insert(0, package_main)
        return {
            "package_main": package_main,
            "files": files,
            "expo_router_path": cls._existing_relative_directory(project_path, "app"),
        }

    @staticmethod
    def _existing_relative_file(project_path: Path, value: object) -> str:
        if not isinstance(value, str) or not value.strip():
            return ""
        candidate = (project_path / value.strip()).resolve()
        try:
            relative_path = candidate.relative_to(project_path)
        except ValueError:
            return ""
        return relative_path.as_posix() if candidate.is_file() else ""

    @staticmethod
    def _existing_relative_directory(project_path: Path, value: str) -> str:
        candidate = (project_path / value).resolve()
        try:
            relative_path = candidate.relative_to(project_path)
        except ValueError:
            return ""
        return relative_path.as_posix() if candidate.is_dir() else ""

    @staticmethod
    def _uses_typescript(
        project_path: Path,
        packages: dict[str, Any],
        entrypoints: dict[str, object],
    ) -> bool:
        if (project_path / "tsconfig.json").is_file() or "typescript" in packages:
            return True
        files = entrypoints.get("files")
        if isinstance(files, list) and any(str(path).endswith((".ts", ".tsx")) for path in files):
            return True
        expo_router_path = entrypoints.get("expo_router_path")
        expo_router = project_path / str(expo_router_path) if expo_router_path else None
        return bool(
            expo_router
            and any(path.is_file() and path.suffix.lower() in {".ts", ".tsx"} for path in expo_router.rglob("*"))
        )

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
