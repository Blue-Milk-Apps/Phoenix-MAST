"""Static metadata extraction for Flutter source projects."""

from __future__ import annotations

import json
import plistlib
import re
from dataclasses import replace
from pathlib import Path
from typing import Any

import yaml

from adapters.scanners.android import NativeAndroidSourceMetadataScanner
from domain.models import ScanConfig, ScanResult, ScanType
from ports.scanner_port import ScannerPort
from utilities.plist_report import PlistReportBuilder


class FlutterSourceMetadataScanner(ScannerPort):
    """Normalize Flutter pubspec metadata without executing project code."""

    SCHEMA_VERSION = "1.0"
    REPORT_PATH = "project_metadata.json"
    PLATFORM_DIRECTORIES = ("android", "ios", "web", "linux", "macos", "windows")
    IOS_EXCLUDED_DIRECTORIES = frozenset({".symlinks", "build", "deriveddata", "pods", "vendor"})
    XCODE_BUILD_SETTING_PATTERN = re.compile(r"^\s*([A-Za-z0-9_]+)\s*=\s*(.*?)\s*;\s*$", re.MULTILINE)
    XCODE_VARIABLE_PATTERN = re.compile(r"\$\(([^)]+)\)")

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

        payload = self._metadata_payload(config, project_path, pubspec_path, pubspec)
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
        config: ScanConfig,
        project_path: Path,
        pubspec_path: Path,
        pubspec: dict[str, Any],
    ) -> dict[str, Any]:
        lock_path = project_path / "pubspec.lock"
        resolved_dependencies, warnings = self._resolved_dependencies(lock_path)
        version, version_name, version_code = self._version_parts(pubspec.get("version"))
        environment = self._mapping(pubspec.get("environment"))
        android, android_warnings = self._android_metadata(
            config,
            project_path,
            version_name=version_name,
            version_code=version_code,
        )
        warnings.extend(android_warnings)
        ios, ios_warnings = self._ios_metadata(
            project_path,
            package_name=self._text(pubspec.get("name")),
            version_name=version_name,
            version_code=version_code,
        )
        warnings.extend(ios_warnings)

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
            "android": android,
            "ios": ios,
            "dependencies": {
                "direct": self._declared_dependencies(pubspec.get("dependencies")),
                "development": self._declared_dependencies(pubspec.get("dev_dependencies")),
                "resolved": resolved_dependencies,
            },
        }

    def _android_metadata(
        self,
        config: ScanConfig,
        project_path: Path,
        *,
        version_name: str,
        version_code: str,
    ) -> tuple[dict[str, Any], list[str]]:
        android_path = project_path / "android"
        if not android_path.is_dir():
            return {"available": False, "project_path": "", "metadata": None}, []

        android_config = replace(config, project_path=android_path)
        result = NativeAndroidSourceMetadataScanner().scan(android_config)[0]
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

        identity = self._mapping(metadata.get("identity"))
        if not self._text(identity.get("version_name")):
            identity["version_name"] = version_name
        if not self._text(identity.get("version_code")):
            identity["version_code"] = version_code
        metadata["identity"] = identity

        extraction = self._mapping(metadata.get("extraction"))
        nested_warnings = extraction.get("warnings")
        warnings = (
            [f"Android metadata: {self._text(item)}" for item in nested_warnings if self._text(item)]
            if isinstance(nested_warnings, list)
            else []
        )
        return {"available": True, "project_path": "android", "metadata": metadata}, warnings

    def _ios_metadata(
        self,
        project_path: Path,
        *,
        package_name: str,
        version_name: str,
        version_code: str,
    ) -> tuple[dict[str, Any], list[str]]:
        ios_path = project_path / "ios"
        unavailable = {"available": False, "project_path": "", "metadata": None}
        if not ios_path.is_dir():
            return unavailable, []

        warnings: list[str] = []
        info_plist_path = self._ios_info_plist(ios_path)
        if info_plist_path is None:
            return (
                {"available": True, "project_path": "ios", "metadata": None},
                ["iOS metadata: No application Info.plist file was found."],
            )

        info_plist = self._load_ios_plist(info_plist_path, ios_path, warnings)
        if info_plist is None:
            return {"available": True, "project_path": "ios", "metadata": None}, warnings

        xcode_project_path = self._xcode_project_file(ios_path)
        xcode_settings = self._xcode_build_settings(xcode_project_path, ios_path, warnings)
        product_name = self._xcode_setting(xcode_settings, "PRODUCT_NAME") or package_name
        variables = {
            "EXECUTABLE_NAME": self._xcode_setting(xcode_settings, "EXECUTABLE_NAME") or product_name,
            "FLUTTER_BUILD_NAME": version_name,
            "FLUTTER_BUILD_NUMBER": version_code,
            "PRODUCT_BUNDLE_IDENTIFIER": self._xcode_setting(xcode_settings, "PRODUCT_BUNDLE_IDENTIFIER"),
            "PRODUCT_NAME": product_name,
        }

        report_builder = PlistReportBuilder(
            scanner_name=self.name,
            scan_type=self.scan_type,
            description=self.description,
            base_path=ios_path,
            output_format="json",
        )
        identity = report_builder._app_meta(info_plist)
        for key, value in list(identity.items()):
            if isinstance(value, str):
                identity[key] = self._resolve_xcode_variables(value, variables, warnings, key)
        if not self._text(identity.get("minimum_os")):
            identity["minimum_os"] = self._xcode_setting(xcode_settings, "IPHONEOS_DEPLOYMENT_TARGET")

        entitlements = self._ios_supporting_plists(
            ios_path,
            suffix=".entitlements",
            detail_builder=report_builder._entitlement_details,
            warnings=warnings,
        )
        privacy_manifests = self._ios_supporting_plists(
            ios_path,
            suffix=".xcprivacy",
            detail_builder=report_builder._privacy_manifest_details,
            warnings=warnings,
        )
        metadata = {
            "info_plist_path": info_plist_path.relative_to(ios_path).as_posix(),
            "xcode_project_path": (
                xcode_project_path.relative_to(ios_path).as_posix() if xcode_project_path is not None else ""
            ),
            "identity": identity,
            "permissions": report_builder._permission_details(info_plist),
            "app_transport_security": report_builder._transport_security_details(info_plist),
            "url_schemes": report_builder._url_scheme_details(info_plist),
            "background_modes": report_builder._background_modes(info_plist),
            "entitlements": entitlements,
            "privacy_manifests": privacy_manifests,
        }
        return {"available": True, "project_path": "ios", "metadata": metadata}, warnings

    def _ios_info_plist(self, ios_path: Path) -> Path | None:
        runner_info = ios_path / "Runner" / "Info.plist"
        if runner_info.is_file():
            return runner_info
        return next(
            (
                path
                for path in sorted(ios_path.rglob("Info.plist"))
                if path.is_file() and not self._excluded_ios_path(path, ios_path)
            ),
            None,
        )

    def _xcode_project_file(self, ios_path: Path) -> Path | None:
        runner_project = ios_path / "Runner.xcodeproj" / "project.pbxproj"
        if runner_project.is_file():
            return runner_project
        return next(
            (path for path in sorted(ios_path.glob("*.xcodeproj/project.pbxproj")) if path.is_file()),
            None,
        )

    def _xcode_build_settings(
        self,
        project_file: Path | None,
        ios_path: Path,
        warnings: list[str],
    ) -> dict[str, list[str]]:
        if project_file is None:
            return {}
        try:
            content = project_file.read_text(encoding="utf-8")
        except OSError as exc:
            relative_path = project_file.relative_to(ios_path).as_posix()
            warnings.append(f"iOS metadata: Unable to read {relative_path}: {exc}")
            return {}

        settings: dict[str, list[str]] = {}
        for key, raw_value in self.XCODE_BUILD_SETTING_PATTERN.findall(content):
            value = raw_value.strip().strip('"')
            if value and value not in settings.setdefault(key, []):
                settings[key].append(value)
        return settings

    @staticmethod
    def _xcode_setting(settings: dict[str, list[str]], name: str) -> str:
        values = settings.get(name, [])
        return next((value for value in values if "$(" not in value), values[0] if values else "")

    def _resolve_xcode_variables(
        self,
        value: str,
        variables: dict[str, str],
        warnings: list[str],
        field_name: str,
    ) -> str:
        unresolved: set[str] = set()

        def replacement(match: re.Match[str]) -> str:
            expression = match.group(1)
            name = expression.split(":", 1)[0]
            replacement_value = variables.get(name, "")
            if not replacement_value:
                unresolved.add(expression)
                return match.group(0)
            return replacement_value

        resolved = self.XCODE_VARIABLE_PATTERN.sub(replacement, value)
        for expression in sorted(unresolved):
            warnings.append(f"iOS metadata: Unable to resolve $({expression}) in {field_name}.")
        return resolved

    def _ios_supporting_plists(
        self,
        ios_path: Path,
        *,
        suffix: str,
        detail_builder: Any,
        warnings: list[str],
    ) -> list[dict[str, Any]]:
        artifacts: list[dict[str, Any]] = []
        for path in sorted(ios_path.rglob(f"*{suffix}")):
            if not path.is_file() or self._excluded_ios_path(path, ios_path):
                continue
            data = self._load_ios_plist(path, ios_path, warnings)
            artifacts.append(
                {
                    "path": path.relative_to(ios_path).as_posix(),
                    "metadata": detail_builder(data) if data is not None else None,
                }
            )
        return artifacts

    @staticmethod
    def _load_ios_plist(path: Path, ios_path: Path, warnings: list[str]) -> dict[str, Any] | None:
        try:
            with path.open("rb") as handle:
                data = plistlib.load(handle)
        except (OSError, plistlib.InvalidFileException) as exc:
            relative_path = path.relative_to(ios_path).as_posix()
            warnings.append(f"iOS metadata: Unable to parse {relative_path}: {exc}")
            return None
        if not isinstance(data, dict):
            relative_path = path.relative_to(ios_path).as_posix()
            warnings.append(f"iOS metadata: {relative_path} does not contain a plist mapping.")
            return None
        return data

    def _excluded_ios_path(self, path: Path, ios_path: Path) -> bool:
        relative_parts = {part.lower() for part in path.relative_to(ios_path).parts}
        return bool(relative_parts.intersection(self.IOS_EXCLUDED_DIRECTORIES))

    def _resolved_dependencies(self, lock_path: Path) -> tuple[list[dict[str, str]], list[str]]:
        if not lock_path.is_file():
            return [], ["No pubspec.lock file found; resolved dependencies were not assessed."]

        try:
            lock_data = yaml.safe_load(lock_path.read_text(encoding="utf-8"))
        except (OSError, yaml.YAMLError) as exc:
            return [], [f"Unable to parse {lock_path.name}; resolved dependencies were not assessed: {exc}"]

        if not isinstance(lock_data, dict) or not isinstance(lock_data.get("packages"), dict):
            return [], [
                f"{lock_path.name} does not contain a packages mapping; resolved dependencies were not assessed."
            ]

        dependencies: list[dict[str, str]] = []
        warnings: list[str] = []
        for name, value in sorted(lock_data["packages"].items()):
            if not isinstance(value, dict):
                warnings.append(f"Unable to read locked dependency metadata for {name}.")
                continue
            dependencies.append(self._resolved_dependency(str(name), value))
        return dependencies, warnings

    def _resolved_dependency(self, name: str, value: dict[str, Any]) -> dict[str, str]:
        source = self._text(value.get("source")) or "unknown"
        description = value.get("description")
        details = self._mapping(description)
        return {
            "name": name,
            "version": self._text(value.get("version")),
            "dependency_kind": self._dependency_kind(value.get("dependency")),
            "source": source,
            "hosted_url": self._text(details.get("url")) if source == "hosted" else "",
            "vcs_url": self._text(details.get("url")) if source == "git" else "",
            "path": self._text(details.get("path")) if source == "path" else "",
        }

    @staticmethod
    def _dependency_kind(value: object) -> str:
        normalized = FlutterSourceMetadataScanner._text(value).lower()
        if normalized == "direct main":
            return "direct"
        if normalized == "direct dev":
            return "development"
        if normalized == "transitive":
            return "transitive"
        return "unknown"

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
