"""Static metadata extraction for React Native source projects."""

from __future__ import annotations

import json
import plistlib
import re
from collections.abc import Callable
from dataclasses import replace
from pathlib import Path
from typing import Any

from adapters.scanners.android import NativeAndroidSourceMetadataScanner
from domain.models import ScanConfig, ScanResult, ScanType
from ports.scanner_port import ScannerPort
from utilities.plist_report import PlistReportBuilder


class ReactNativeMetadataScanner(ScannerPort):
    """Normalize React Native project metadata without executing project code."""

    SCHEMA_VERSION = "1.0"
    REPORT_PATH = "project_metadata.json"
    LOCKFILE_PACKAGE_MANAGERS = (
        ("pnpm-lock.yaml", "pnpm"),
        ("yarn.lock", "yarn"),
        ("package-lock.json", "npm"),
    )
    IOS_EXCLUDED_DIRECTORIES = frozenset({"build", "deriveddata", "pods", "vendor"})
    XCODE_BUILD_SETTING_PATTERN = re.compile(r"^\s*([A-Za-z0-9_]+)\s*=\s*(.*?)\s*;\s*$", re.MULTILINE)
    XCODE_VARIABLE_PATTERN = re.compile(r"\$\(([^)]+)\)|\$\{([^}]+)\}")

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
        ios, ios_warnings = self._ios_metadata(project_path)
        warnings.extend(ios_warnings)
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
            "ios": ios,
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
    def _ios_metadata(cls, project_path: Path) -> tuple[dict[str, object], list[str]]:
        ios_path = project_path / "ios"
        if not ios_path.is_dir():
            return {"available": False, "project_path": "", "metadata": None}, []

        warnings: list[str] = []
        project_file = cls._ios_project_file(ios_path)
        settings = cls._xcode_build_settings(project_file, ios_path, warnings)
        info_plist = cls._ios_info_plist(ios_path, settings)
        if project_file is None:
            warnings.append("iOS metadata: No Xcode project file was found.")
        if info_plist is None:
            warnings.append("iOS metadata: No application Info.plist file was found.")
            return {"available": True, "project_path": "ios", "metadata": None}, warnings

        plist = cls._load_ios_plist(info_plist, ios_path, warnings)
        if plist is None:
            return {"available": True, "project_path": "ios", "metadata": None}, warnings

        report_builder = cls._plist_report_builder(ios_path)
        identity = report_builder._app_meta(plist)
        variables = cls._ios_identity_variables(settings)
        for key, value in list(identity.items()):
            if isinstance(value, str):
                identity[key] = cls._resolve_xcode_variables(value, variables, warnings, f"identity.{key}")
        if not cls._text(identity.get("bundle_identifier")):
            identity["bundle_identifier"] = variables["PRODUCT_BUNDLE_IDENTIFIER"]
        if not cls._text(identity.get("bundle_name")):
            identity["bundle_name"] = variables["PRODUCT_NAME"]
        if not cls._text(identity.get("display_name")):
            identity["display_name"] = variables["PRODUCT_NAME"]
        if not cls._text(identity.get("executable")):
            identity["executable"] = variables["EXECUTABLE_NAME"]
        if not cls._text(identity.get("version")):
            identity["version"] = variables["MARKETING_VERSION"]
        if not cls._text(identity.get("build")):
            identity["build"] = variables["CURRENT_PROJECT_VERSION"]
        if not cls._text(identity.get("minimum_os")):
            identity["minimum_os"] = variables["IPHONEOS_DEPLOYMENT_TARGET"]

        metadata = {
            "xcode_project_path": cls._relative(ios_path, project_file) if project_file else "",
            "info_plist_path": cls._relative(ios_path, info_plist),
            "identity": identity,
            "permissions": report_builder._permission_details(plist),
            "app_transport_security": report_builder._transport_security_details(plist),
            "url_schemes": report_builder._url_scheme_details(plist),
            "background_modes": report_builder._background_modes(plist),
            "entitlements": cls._ios_supporting_plists(
                ios_path,
                suffix=".entitlements",
                detail_builder=report_builder._entitlement_details,
                warnings=warnings,
            ),
            "privacy_manifests": cls._ios_supporting_plists(
                ios_path,
                suffix=".xcprivacy",
                detail_builder=report_builder._privacy_manifest_details,
                warnings=warnings,
            ),
        }
        return {"available": True, "project_path": "ios", "metadata": metadata}, warnings

    @classmethod
    def _load_ios_plist(
        cls,
        path: Path,
        ios_path: Path,
        warnings: list[str],
    ) -> dict[str, Any] | None:
        try:
            with path.open("rb") as handle:
                value = plistlib.load(handle)
        except (OSError, plistlib.InvalidFileException) as exc:
            warnings.append(f"iOS metadata: Unable to parse {cls._relative(ios_path, path)}: {exc}")
            return None
        if not isinstance(value, dict):
            warnings.append(f"iOS metadata: {cls._relative(ios_path, path)} does not contain a plist mapping.")
            return None
        return value

    @classmethod
    def _plist_report_builder(
        cls,
        ios_path: Path,
    ) -> PlistReportBuilder:
        return PlistReportBuilder(
            scanner_name="React Native Metadata Scanner",
            scan_type=ScanType.REACT_NATIVE_METADATA,
            description="Static iOS metadata embedded in a React Native project.",
            base_path=ios_path,
            output_format="json",
        )

    @classmethod
    def _ios_supporting_plists(
        cls,
        ios_path: Path,
        *,
        suffix: str,
        detail_builder: Callable[[object], dict[str, object]],
        warnings: list[str],
    ) -> list[dict[str, object]]:
        artifacts: list[dict[str, object]] = []
        for path in sorted(ios_path.rglob("*")):
            if not path.is_file() or not path.name.lower().endswith(suffix) or cls._excluded_ios_path(path, ios_path):
                continue
            data = cls._load_ios_plist(path, ios_path, warnings)
            artifacts.append(
                {
                    "path": cls._relative(ios_path, path),
                    "metadata": detail_builder(data) if data is not None else None,
                }
            )
        return artifacts

    @classmethod
    def _ios_identity_variables(cls, settings: dict[str, list[str]]) -> dict[str, str]:
        variables = {
            name: cls._static_xcode_setting(settings, name)
            for name in (
                "CURRENT_PROJECT_VERSION",
                "EXECUTABLE_NAME",
                "IPHONEOS_DEPLOYMENT_TARGET",
                "MARKETING_VERSION",
                "PRODUCT_BUNDLE_IDENTIFIER",
                "PRODUCT_MODULE_NAME",
                "PRODUCT_NAME",
            )
        }
        if not variables["EXECUTABLE_NAME"]:
            variables["EXECUTABLE_NAME"] = variables["PRODUCT_NAME"]
        if not variables["PRODUCT_MODULE_NAME"]:
            variables["PRODUCT_MODULE_NAME"] = variables["PRODUCT_NAME"]
        return variables

    @staticmethod
    def _static_xcode_setting(settings: dict[str, list[str]], name: str) -> str:
        return next((value for value in settings.get(name, []) if "$" not in value), "")

    @classmethod
    def _resolve_xcode_variables(
        cls,
        value: str,
        variables: dict[str, str],
        warnings: list[str],
        field_name: str,
    ) -> str:
        unresolved: set[str] = set()

        def replacement(match: re.Match[str]) -> str:
            expression = match.group(1) or match.group(2) or ""
            name = expression.split(":", 1)[0]
            replacement_value = variables.get(name, "")
            if not replacement_value:
                unresolved.add(expression)
                return match.group(0)
            return replacement_value

        resolved = cls.XCODE_VARIABLE_PATTERN.sub(replacement, value)
        for expression in sorted(unresolved):
            warnings.append(f"iOS metadata: Unable to resolve $({expression}) in {field_name}.")
        return resolved

    @classmethod
    def _ios_project_file(cls, ios_path: Path) -> Path | None:
        candidates = [
            path
            for path in sorted(ios_path.rglob("project.pbxproj"))
            if path.is_file() and path.parent.suffix == ".xcodeproj" and not cls._excluded_ios_path(path, ios_path)
        ]
        return min(
            candidates, key=lambda path: (len(path.relative_to(ios_path).parts), str(path).lower()), default=None
        )

    @classmethod
    def _xcode_build_settings(
        cls,
        project_file: Path | None,
        ios_path: Path,
        warnings: list[str],
    ) -> dict[str, list[str]]:
        if project_file is None:
            return {}
        try:
            content = project_file.read_text(encoding="utf-8")
        except OSError as exc:
            warnings.append(f"iOS metadata: Unable to read {cls._relative(ios_path, project_file)}: {exc}")
            return {}

        settings: dict[str, list[str]] = {}
        for key, raw_value in cls.XCODE_BUILD_SETTING_PATTERN.findall(content):
            value = raw_value.strip().strip('"')
            if value and value not in settings.setdefault(key, []):
                settings[key].append(value)
        return settings

    @classmethod
    def _ios_info_plist(cls, ios_path: Path, settings: dict[str, list[str]]) -> Path | None:
        product_names = cls._xcode_setting_values(settings, "PRODUCT_NAME")
        variables = {
            "PRODUCT_NAME": next((name for name in product_names if "$" not in name), ""),
        }
        for raw_path in cls._xcode_setting_values(settings, "INFOPLIST_FILE"):
            candidate = cls._resolve_ios_path_setting(ios_path, raw_path, variables)
            if candidate is not None and candidate.is_file() and not cls._excluded_ios_path(candidate, ios_path):
                return candidate

        candidates = [
            path
            for path in sorted(ios_path.rglob("Info.plist"))
            if path.is_file() and not cls._excluded_ios_path(path, ios_path)
        ]
        preferred_names = {name.lower() for name in product_names if "$" not in name}
        return min(
            candidates,
            key=lambda path: (
                int(not preferred_names.intersection(part.lower() for part in path.relative_to(ios_path).parts)),
                len(path.relative_to(ios_path).parts),
                str(path).lower(),
            ),
            default=None,
        )

    @staticmethod
    def _xcode_setting_values(settings: dict[str, list[str]], name: str) -> list[str]:
        return settings.get(name, [])

    @classmethod
    def _resolve_ios_path_setting(
        cls,
        ios_path: Path,
        value: str,
        variables: dict[str, str],
    ) -> Path | None:
        resolved = value
        for expression in ("$(SRCROOT)", "${SRCROOT}", "$(PROJECT_DIR)", "${PROJECT_DIR}"):
            resolved = resolved.replace(expression, str(ios_path))
        for name, replacement in variables.items():
            if replacement:
                resolved = resolved.replace(f"$({name})", replacement).replace(f"${{{name}}}", replacement)
        if "$(" in resolved or "${" in resolved:
            return None

        candidate = Path(resolved)
        if not candidate.is_absolute():
            candidate = ios_path / candidate
        candidate = candidate.resolve()
        try:
            candidate.relative_to(ios_path)
        except ValueError:
            return None
        return candidate

    @classmethod
    def _excluded_ios_path(cls, path: Path, ios_path: Path) -> bool:
        try:
            relative_parts = {part.lower() for part in path.resolve().relative_to(ios_path.resolve()).parts}
        except ValueError:
            return True
        return bool(relative_parts.intersection(cls.IOS_EXCLUDED_DIRECTORIES))

    @staticmethod
    def _relative(base_path: Path, path: Path) -> str:
        return path.relative_to(base_path).as_posix()

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
