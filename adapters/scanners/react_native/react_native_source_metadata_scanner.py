"""Static metadata extraction for React Native source projects."""

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


class ReactNativeSourceMetadataScanner(ScannerPort):
    """Normalize React Native and embedded mobile-platform metadata."""

    SCHEMA_VERSION = "1.0"
    REPORT_PATH = "project_metadata.json"
    DEPENDENCY_SECTIONS = {
        "dependencies": "direct",
        "devDependencies": "development",
        "optionalDependencies": "optional",
        "peerDependencies": "peer",
    }
    LOCK_FILE_NAMES = ("package-lock.json", "pnpm-lock.yaml", "yarn.lock")
    IOS_EXCLUDED_DIRECTORIES = frozenset({"build", "deriveddata", "pods", "vendor"})
    XCODE_BUILD_SETTING_PATTERN = re.compile(r"^\s*([A-Za-z0-9_]+)\s*=\s*(.*?)\s*;\s*$", re.MULTILINE)
    XCODE_VARIABLE_PATTERN = re.compile(r"\$\(([^)]+)\)|\$\{([^}]+)\}")

    @property
    def scan_type(self) -> ScanType:
        return ScanType.REACT_NATIVE_SOURCE_METADATA

    @property
    def name(self) -> str:
        return "React Native Source Metadata Scanner"

    @property
    def description(self) -> str:
        return "Static React Native package, runtime, dependency, Android, and iOS metadata extraction."

    def is_available(self) -> bool:
        return True

    def scan(self, config: ScanConfig) -> list[ScanResult]:
        project_path = config.project_path.resolve()
        if not project_path.is_dir():
            return [self._failure(f"React Native source target is not a directory: {project_path}")]

        package_path = project_path / "package.json"
        package_json, warnings = self._json_mapping(package_path, required=False)
        if package_json is None:
            package_json = {}
            warnings.insert(0, "No package.json file found at the declared React Native project root.")

        payload = self._metadata_payload(config, project_path, package_path, package_json, warnings)
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
        package_path: Path,
        package_json: dict[str, Any],
        warnings: list[str],
    ) -> dict[str, Any]:
        app_json_path = project_path / "app.json"
        app_json, app_warnings = self._json_mapping(app_json_path, required=False)
        warnings.extend(app_warnings)
        expo = self._mapping((app_json or {}).get("expo"))
        dynamic_configs = [
            path.relative_to(project_path).as_posix()
            for path in (project_path / "app.config.js", project_path / "app.config.ts")
            if path.is_file()
        ]
        if dynamic_configs:
            warnings.append(
                "Dynamic Expo configuration was detected but not executed: " + ", ".join(dynamic_configs) + "."
            )

        declared = self._declared_dependencies(package_json)
        if not any(item["name"] == "react-native" for item in declared):
            warnings.append(
                "package.json does not declare react-native; the React Native target type was supplied by the caller."
            )

        lock_path = next(
            (project_path / name for name in self.LOCK_FILE_NAMES if (project_path / name).is_file()), None
        )
        resolved, lock_warnings = self._resolved_dependencies(lock_path)
        warnings.extend(lock_warnings)

        android, android_warnings = self._android_metadata(config, project_path)
        warnings.extend(android_warnings)
        ios, ios_warnings = self._ios_metadata(project_path)
        warnings.extend(ios_warnings)

        expo_platforms = (
            {str(value).strip().lower() for value in expo.get("platforms", []) if isinstance(value, str)}
            if isinstance(expo.get("platforms"), list)
            else set()
        )
        android_detected = (
            (project_path / "android").is_dir() or "android" in expo_platforms or isinstance(expo.get("android"), dict)
        )
        ios_detected = (project_path / "ios").is_dir() or "ios" in expo_platforms or isinstance(expo.get("ios"), dict)

        engines = self._mapping(package_json.get("engines"))
        return {
            "schema_version": self.SCHEMA_VERSION,
            "extraction": {
                "status": "partial" if warnings else "complete",
                "warnings": list(dict.fromkeys(warnings)),
            },
            "project": {
                "project_path": str(project_path),
                "package_json_path": "package.json" if package_path.is_file() else "",
                "app_json_path": "app.json" if app_json_path.is_file() else "",
                "lock_file_path": lock_path.name if lock_path else "",
                "dynamic_expo_config_paths": dynamic_configs,
            },
            "identity": {
                "package_name": self._text(package_json.get("name")),
                "display_name": self._text(expo.get("name") or (app_json or {}).get("displayName")),
                "version": self._text(package_json.get("version") or expo.get("version")),
                "description": self._text(package_json.get("description")),
                "entry_point": self._text(package_json.get("main")),
                "private": package_json.get("private") if isinstance(package_json.get("private"), bool) else None,
            },
            "runtime": {
                "react_native_constraint": self._dependency_constraint(package_json, "react-native"),
                "react_constraint": self._dependency_constraint(package_json, "react"),
                "expo_constraint": self._dependency_constraint(package_json, "expo"),
                "node_constraint": self._text(engines.get("node")),
                "package_manager": self._text(package_json.get("packageManager")),
            },
            "platforms": {"android": android_detected, "ios": ios_detected},
            "expo": self._expo_metadata(expo, bool(expo)),
            "android": android,
            "ios": ios,
            "dependencies": {
                "declared": declared,
                "resolved": resolved,
            },
        }

    def _android_metadata(self, config: ScanConfig, project_path: Path) -> tuple[dict[str, Any], list[str]]:
        android_path = project_path / "android"
        if not android_path.is_dir():
            return {"available": False, "project_path": "", "metadata": None}, []

        result = NativeAndroidSourceMetadataScanner().scan(replace(config, project_path=android_path))[0]
        if not result.success:
            reason = result.error_message or "Android source metadata extraction did not complete."
            return {"available": True, "project_path": "android", "metadata": None}, [f"Android metadata: {reason}"]
        try:
            metadata = json.loads(result.raw_output)
        except json.JSONDecodeError as exc:
            return {"available": True, "project_path": "android", "metadata": None}, [
                f"Android metadata output was not valid JSON: {exc}"
            ]
        extraction = self._mapping(metadata.get("extraction")) if isinstance(metadata, dict) else {}
        nested_warnings = extraction.get("warnings")
        warnings = (
            [f"Android metadata: {self._text(item)}" for item in nested_warnings if self._text(item)]
            if isinstance(nested_warnings, list)
            else []
        )
        return {"available": True, "project_path": "android", "metadata": metadata}, warnings

    def _ios_metadata(self, project_path: Path) -> tuple[dict[str, Any], list[str]]:
        ios_path = project_path / "ios"
        if not ios_path.is_dir():
            return {"available": False, "project_path": "", "metadata": None}, []

        warnings: list[str] = []
        info_path = self._ios_info_plist(ios_path)
        if info_path is None:
            return {"available": True, "project_path": "ios", "metadata": None}, [
                "iOS metadata: No application Info.plist file was found."
            ]
        info = self._load_plist(info_path, ios_path, warnings)
        if info is None:
            return {"available": True, "project_path": "ios", "metadata": None}, warnings

        project_file = next(
            (path for path in sorted(ios_path.glob("*.xcodeproj/project.pbxproj")) if path.is_file()),
            None,
        )
        settings = self._xcode_settings(project_file, ios_path, warnings)
        variables = {
            "PRODUCT_NAME": self._xcode_setting(settings, "PRODUCT_NAME"),
            "EXECUTABLE_NAME": self._xcode_setting(settings, "EXECUTABLE_NAME"),
            "PRODUCT_BUNDLE_IDENTIFIER": self._xcode_setting(settings, "PRODUCT_BUNDLE_IDENTIFIER"),
            "MARKETING_VERSION": self._xcode_setting(settings, "MARKETING_VERSION"),
            "CURRENT_PROJECT_VERSION": self._xcode_setting(settings, "CURRENT_PROJECT_VERSION"),
        }
        builder = PlistReportBuilder(
            scanner_name=self.name,
            scan_type=self.scan_type,
            description=self.description,
            base_path=ios_path,
            output_format="json",
        )
        identity = builder._app_meta(info)
        for key, value in list(identity.items()):
            if isinstance(value, str):
                identity[key] = self._resolve_xcode_variables(value, variables, warnings, key)
        if not self._text(identity.get("minimum_os")):
            identity["minimum_os"] = self._xcode_setting(settings, "IPHONEOS_DEPLOYMENT_TARGET")

        metadata = {
            "info_plist_path": info_path.relative_to(ios_path).as_posix(),
            "xcode_project_path": project_file.relative_to(ios_path).as_posix() if project_file else "",
            "identity": identity,
            "permissions": builder._permission_details(info),
            "app_transport_security": builder._transport_security_details(info),
            "url_schemes": builder._url_scheme_details(info),
            "background_modes": builder._background_modes(info),
            "entitlements": self._supporting_plists(
                ios_path,
                ".entitlements",
                lambda data: self._entitlement_metadata(builder, data),
                warnings,
            ),
            "privacy_manifests": self._supporting_plists(
                ios_path, ".xcprivacy", builder._privacy_manifest_details, warnings
            ),
        }
        return {"available": True, "project_path": "ios", "metadata": metadata}, warnings

    def _ios_info_plist(self, ios_path: Path) -> Path | None:
        return next(
            (
                path
                for path in sorted(ios_path.rglob("Info.plist"))
                if path.is_file() and not self._excluded_ios_path(path, ios_path)
            ),
            None,
        )

    def _xcode_settings(self, project_file: Path | None, ios_path: Path, warnings: list[str]) -> dict[str, list[str]]:
        if project_file is None:
            return {}
        try:
            content = project_file.read_text(encoding="utf-8")
        except OSError as exc:
            warnings.append(f"iOS metadata: Unable to read {project_file.relative_to(ios_path)}: {exc}")
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
        return next((value for value in values if "$(" not in value and "${" not in value), values[0] if values else "")

    def _resolve_xcode_variables(
        self, value: str, variables: dict[str, str], warnings: list[str], field_name: str
    ) -> str:
        unresolved: set[str] = set()

        def replacement(match: re.Match[str]) -> str:
            expression = match.group(1) or match.group(2) or ""
            name = expression.split(":", 1)[0]
            if variables.get(name):
                return variables[name]
            unresolved.add(expression)
            return match.group(0)

        resolved = self.XCODE_VARIABLE_PATTERN.sub(replacement, value)
        for expression in sorted(unresolved):
            warnings.append(f"iOS metadata: Unable to resolve build variable {expression} in {field_name}.")
        return resolved

    def _supporting_plists(
        self, ios_path: Path, suffix: str, detail_builder: Any, warnings: list[str]
    ) -> list[dict[str, Any]]:
        artifacts: list[dict[str, Any]] = []
        for path in sorted(ios_path.rglob(f"*{suffix}")):
            if not path.is_file() or self._excluded_ios_path(path, ios_path):
                continue
            data = self._load_plist(path, ios_path, warnings)
            artifacts.append(
                {
                    "path": path.relative_to(ios_path).as_posix(),
                    "metadata": detail_builder(data) if data is not None else None,
                }
            )
        return artifacts

    @staticmethod
    def _entitlement_metadata(builder: PlistReportBuilder, data: dict[str, Any]) -> dict[str, Any]:
        metadata = builder._entitlement_details(data)
        risky_keys = {
            "get-task-allow",
            "com.apple.security.cs.allow-dyld-environment-variables",
            "com.apple.security.cs.allow-unsigned-executable-memory",
            "com.apple.security.cs.disable-executable-page-protection",
            "com.apple.security.cs.disable-library-validation",
        }
        metadata["security_risk_keys"] = sorted(
            key
            for key, value in data.items()
            if (key in risky_keys and value is True) or str(key).startswith("com.apple.private.")
        )
        return metadata

    @staticmethod
    def _load_plist(path: Path, ios_path: Path, warnings: list[str]) -> dict[str, Any] | None:
        try:
            with path.open("rb") as handle:
                data = plistlib.load(handle)
        except (OSError, plistlib.InvalidFileException) as exc:
            warnings.append(f"iOS metadata: Unable to parse {path.relative_to(ios_path)}: {exc}")
            return None
        if not isinstance(data, dict):
            warnings.append(f"iOS metadata: {path.relative_to(ios_path)} is not a plist mapping.")
            return None
        return data

    def _excluded_ios_path(self, path: Path, ios_path: Path) -> bool:
        return bool(
            {part.lower() for part in path.relative_to(ios_path).parts}.intersection(self.IOS_EXCLUDED_DIRECTORIES)
        )

    def _declared_dependencies(self, package_json: dict[str, Any]) -> list[dict[str, str]]:
        dependencies: list[dict[str, str]] = []
        for section, scope in self.DEPENDENCY_SECTIONS.items():
            values = self._mapping(package_json.get(section))
            dependencies.extend(
                {
                    "name": str(name),
                    "constraint": self._text(constraint),
                    "scope": scope,
                }
                for name, constraint in sorted(values.items())
            )
        return dependencies

    def _dependency_constraint(self, package_json: dict[str, Any], name: str) -> str:
        for section in self.DEPENDENCY_SECTIONS:
            value = self._mapping(package_json.get(section)).get(name)
            if isinstance(value, str) and value.strip():
                return value.strip()
        return ""

    def _resolved_dependencies(self, lock_path: Path | None) -> tuple[list[dict[str, str]], list[str]]:
        if lock_path is None:
            return [], ["No supported JavaScript lockfile found; resolved dependencies were not assessed."]
        if lock_path.name == "yarn.lock":
            return self._yarn_dependencies(lock_path)
        if lock_path.name == "package-lock.json":
            data, warnings = self._json_mapping(lock_path, required=True)
            if data is None:
                return [], warnings
            packages = self._mapping(data.get("packages"))
            resolved = []
            for location, value in sorted(packages.items()):
                record = self._mapping(value)
                if not location or not record:
                    continue
                resolved.append(
                    {
                        "name": self._text(record.get("name")) or str(location).rsplit("node_modules/", 1)[-1],
                        "version": self._text(record.get("version")),
                        "scope": "development" if record.get("dev") is True else "resolved",
                    }
                )
            return resolved, warnings
        try:
            data = yaml.safe_load(lock_path.read_text(encoding="utf-8"))
        except (OSError, yaml.YAMLError) as exc:
            return [], [f"Unable to parse {lock_path.name}; resolved dependencies were not assessed: {exc}"]
        packages = self._mapping(self._mapping(data).get("packages"))
        resolved = []
        for key in sorted(packages):
            name, version = self._pnpm_package_parts(str(key))
            if name:
                resolved.append({"name": name, "version": version, "scope": "resolved"})
        return resolved, []

    def _yarn_dependencies(self, lock_path: Path) -> tuple[list[dict[str, str]], list[str]]:
        try:
            lines = lock_path.read_text(encoding="utf-8").splitlines()
        except OSError as exc:
            return [], [f"Unable to read {lock_path.name}; resolved dependencies were not assessed: {exc}"]

        resolved: list[dict[str, str]] = []
        current_name = ""
        for line in lines:
            if line and not line[0].isspace() and line.rstrip().endswith(":"):
                selector = line.rstrip()[:-1].split(",", 1)[0].strip().strip("\"'")
                current_name = "" if selector.startswith("__") else selector.rsplit("@", 1)[0]
                continue
            version_match = re.match(r'^\s+version(?:\s+|:\s*)["\']?([^"\'\s]+)', line)
            if current_name and version_match:
                resolved.append(
                    {
                        "name": current_name,
                        "version": version_match.group(1),
                        "scope": "resolved",
                    }
                )
                current_name = ""

        if not resolved:
            return [], ["yarn.lock was detected but no resolved dependency entries could be normalized."]
        unique = {(item["name"], item["version"]): item for item in resolved}
        return list(unique.values()), []

    @staticmethod
    def _pnpm_package_parts(value: str) -> tuple[str, str]:
        normalized = value.lstrip("/").split("(", 1)[0]
        if "@" not in normalized:
            return normalized, ""
        name, version = normalized.rsplit("@", 1)
        return name, version

    @staticmethod
    def _expo_metadata(expo: dict[str, Any], assessed: bool) -> dict[str, Any]:
        android = expo.get("android") if isinstance(expo.get("android"), dict) else {}
        ios = expo.get("ios") if isinstance(expo.get("ios"), dict) else {}
        platforms = expo.get("platforms") if isinstance(expo.get("platforms"), list) else []
        return {
            "assessed": assessed,
            "platforms": [value for value in platforms if value in {"android", "ios"}],
            "android": {
                "package": str(android.get("package") or "").strip(),
                "version_code": str(android.get("versionCode") or "").strip(),
                "permissions": android.get("permissions") if isinstance(android.get("permissions"), list) else [],
            },
            "ios": {
                "bundle_identifier": str(ios.get("bundleIdentifier") or "").strip(),
                "build_number": str(ios.get("buildNumber") or "").strip(),
                "supports_tablet": ios.get("supportsTablet") if isinstance(ios.get("supportsTablet"), bool) else None,
            },
        }

    @staticmethod
    def _json_mapping(path: Path, *, required: bool) -> tuple[dict[str, Any] | None, list[str]]:
        if not path.is_file():
            return None, [] if not required else [f"No {path.name} file found."]
        try:
            value = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            return None, [f"Unable to parse {path.name}: {exc}"]
        if not isinstance(value, dict):
            return None, [f"{path.name} does not contain a JSON object."]
        return value, []

    @staticmethod
    def _mapping(value: object) -> dict[str, Any]:
        return value if isinstance(value, dict) else {}

    @staticmethod
    def _text(value: object) -> str:
        return str(value).strip() if value is not None else ""

    def _failure(self, error_message: str) -> ScanResult:
        return ScanResult(
            scanner_name=self.name,
            scan_type=self.scan_type,
            success=False,
            error_message=error_message,
            raw_output=json.dumps({"error": error_message, "success": False}, indent=2, sort_keys=True),
            relative_target_path="scan_summary.json",
            description=self.description,
        )
