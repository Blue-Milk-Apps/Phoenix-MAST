"""Static metadata extraction for native Android source projects."""

from __future__ import annotations

import json
import re
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any

from domain.models import ScanConfig, ScanResult, ScanType
from ports.scanner_port import ScannerPort

ANDROID_NAMESPACE = "http://schemas.android.com/apk/res/android"


class NativeAndroidSourceMetadataScanner(ScannerPort):
    """Normalize manifest and Gradle metadata without building the project."""

    SCHEMA_VERSION = "1.0"
    REPORT_PATH = "project_metadata.json"
    EXCLUDED_DIRECTORY_NAMES = frozenset({".gradle", ".idea", "build", "vendor"})
    COMPONENT_TAGS = ("activity", "activity-alias", "service", "receiver", "provider")
    COMPONENT_COLLECTIONS = {
        "activity": "activities",
        "service": "services",
        "receiver": "receivers",
        "provider": "providers",
    }

    @property
    def scan_type(self) -> ScanType:
        return ScanType.NATIVE_ANDROID_SOURCE_METADATA

    @property
    def name(self) -> str:
        return "Native Android Source Metadata Scanner"

    @property
    def description(self) -> str:
        return "Static AndroidManifest.xml, Gradle, and string-resource metadata extraction."

    def is_available(self) -> bool:
        return True

    def scan(self, config: ScanConfig) -> list[ScanResult]:
        project_path = config.project_path.resolve()
        manifest_paths = self._manifest_candidates(project_path)
        if not manifest_paths:
            return [self._failure("No src/main/AndroidManifest.xml file found.", skipped=True)]

        selected_manifest = min(manifest_paths, key=lambda path: self._candidate_rank(project_path, path))
        try:
            payload = self._metadata_payload(project_path, selected_manifest, manifest_paths)
        except (ET.ParseError, OSError) as exc:
            return [self._failure(f"Unable to parse {selected_manifest}: {exc}")]

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

    def _manifest_candidates(self, project_path: Path) -> list[Path]:
        if not project_path.is_dir():
            return []
        return sorted(
            path
            for path in project_path.rglob("AndroidManifest.xml")
            if path.is_file()
            and path.parent.name == "main"
            and path.parent.parent.name == "src"
            and not self.EXCLUDED_DIRECTORY_NAMES.intersection(path.relative_to(project_path).parts)
        )

    def _candidate_rank(self, project_path: Path, manifest_path: Path) -> tuple[int, int, int, int, str]:
        module_path = manifest_path.parents[2]
        build_file = self._build_file(module_path)
        build_text = self._read_text(build_file)
        relative_module = module_path.relative_to(project_path)
        return (
            int(not self._uses_application_plugin(build_text)),
            int(module_path.name != "app"),
            int(not self._has_launcher_activity(manifest_path)),
            len(relative_module.parts),
            relative_module.as_posix().lower(),
        )

    def _metadata_payload(
        self,
        project_path: Path,
        manifest_path: Path,
        manifest_paths: list[Path],
    ) -> dict[str, Any]:
        module_path = manifest_path.parents[2]
        build_file = self._build_file(module_path)
        build_text = self._read_text(build_file)
        settings_file = self._settings_file(project_path)
        settings_text = self._read_text(settings_file)
        warnings: list[str] = []

        gradle = {
            "namespace": self._gradle_literal(build_text, ("namespace",), quoted=True, warnings=warnings),
            "application_id": self._gradle_literal(
                build_text,
                ("applicationId",),
                quoted=True,
                warnings=warnings,
            ),
            "compile_sdk": self._gradle_literal(
                build_text,
                ("compileSdk", "compileSdkVersion"),
                quoted=False,
                warnings=warnings,
            ),
            "min_sdk": self._gradle_literal(
                build_text,
                ("minSdk", "minSdkVersion"),
                quoted=False,
                warnings=warnings,
            ),
            "target_sdk": self._gradle_literal(
                build_text,
                ("targetSdk", "targetSdkVersion"),
                quoted=False,
                warnings=warnings,
            ),
            "version_name": self._gradle_literal(
                build_text,
                ("versionName",),
                quoted=True,
                warnings=warnings,
            ),
            "version_code": self._gradle_literal(
                build_text,
                ("versionCode",),
                quoted=False,
                warnings=warnings,
            ),
        }

        root = ET.parse(manifest_path).getroot()
        manifest_package = str(root.get("package") or "").strip()
        package_name = gradle["application_id"] or manifest_package or gradle["namespace"]
        application_element = root.find("application")
        resources = self._string_resources(module_path)
        app_label = self._resolve_resource(self._android_attr(application_element, "label"), resources)
        project_name = self._root_project_name(settings_text)
        components, deep_links, main_activity = self._components(application_element, package_name)
        permissions = self._permissions(root)

        if len(manifest_paths) > 1:
            warnings.append(f"Multiple main manifests found; selected {self._relative(project_path, manifest_path)}.")

        application = {
            "debuggable": self._boolean_attr(application_element, "debuggable"),
            "allow_backup": self._boolean_attr(application_element, "allowBackup"),
            "uses_cleartext_traffic": self._boolean_attr(application_element, "usesCleartextTraffic"),
            "icon": self._android_attr(application_element, "icon"),
            "theme": self._android_attr(application_element, "theme"),
        }
        return {
            "schema_version": self.SCHEMA_VERSION,
            "extraction": {
                "status": "partial" if warnings else "complete",
                "warnings": list(dict.fromkeys(warnings)),
            },
            "project": {
                "project_path": str(project_path),
                "module_path": self._relative(project_path, module_path),
                "manifest_path": self._relative(project_path, manifest_path),
                "build_file_path": self._relative(project_path, build_file) if build_file else "",
                "manifest_candidates": [self._relative(project_path, path) for path in manifest_paths],
            },
            "identity": {
                "app_name": app_label or project_name or module_path.name,
                "package_name": package_name,
                "namespace": gradle["namespace"],
                "main_activity": main_activity,
                "compile_sdk": gradle["compile_sdk"],
                "min_sdk": gradle["min_sdk"],
                "target_sdk": gradle["target_sdk"],
                "version_name": gradle["version_name"],
                "version_code": gradle["version_code"],
            },
            "application": application,
            "permissions": permissions,
            "components": components,
            "deep_links": deep_links,
        }

    @classmethod
    def _gradle_literal(
        cls,
        content: str,
        names: tuple[str, ...],
        *,
        quoted: bool,
        warnings: list[str],
    ) -> str:
        names_pattern = "|".join(re.escape(name) for name in names)
        value_pattern = r"['\"]([^'\"]+)['\"]" if quoted else r"['\"]?([0-9]+)['\"]?"
        pattern = re.compile(
            rf"(?m)^\s*(?:{names_pattern})\s*(?:=\s*|\s+)\(?\s*{value_pattern}",
        )
        match = pattern.search(content)
        if match:
            return match.group(1).strip()
        if any(re.search(rf"\b{re.escape(name)}\b", content) for name in names):
            warnings.append(f"Unable to resolve dynamic Gradle value: {names[0]}.")
        return ""

    @staticmethod
    def _uses_application_plugin(content: str) -> bool:
        return "com.android.application" in content or "android.application" in content

    @staticmethod
    def _build_file(module_path: Path) -> Path | None:
        for name in ("build.gradle.kts", "build.gradle"):
            candidate = module_path / name
            if candidate.is_file():
                return candidate
        return None

    @staticmethod
    def _settings_file(project_path: Path) -> Path | None:
        for name in ("settings.gradle.kts", "settings.gradle"):
            candidate = project_path / name
            if candidate.is_file():
                return candidate
        return None

    @staticmethod
    def _read_text(path: Path | None) -> str:
        if path is None:
            return ""
        return path.read_text(encoding="utf-8", errors="ignore")

    @staticmethod
    def _root_project_name(content: str) -> str:
        match = re.search(r"(?m)^\s*rootProject\.name\s*=\s*['\"]([^'\"]+)['\"]", content)
        return match.group(1).strip() if match else ""

    def _string_resources(self, module_path: Path) -> dict[str, str]:
        strings_path = module_path / "src" / "main" / "res" / "values" / "strings.xml"
        if not strings_path.is_file():
            return {}
        try:
            root = ET.parse(strings_path).getroot()
        except (ET.ParseError, OSError):
            return {}
        return {
            str(element.get("name")): "".join(element.itertext()).strip()
            for element in root.findall("string")
            if element.get("name")
        }

    @staticmethod
    def _resolve_resource(value: str, resources: dict[str, str]) -> str:
        prefix = "@string/"
        return resources.get(value[len(prefix) :], value) if value.startswith(prefix) else value

    def _permissions(self, root: ET.Element) -> list[dict[str, str]]:
        permissions: list[dict[str, str]] = []
        seen: set[str] = set()
        for element in root:
            if self._local_name(element.tag) not in {"uses-permission", "uses-permission-sdk-23"}:
                continue
            name = self._android_attr(element, "name")
            if not name or name in seen:
                continue
            seen.add(name)
            permissions.append(
                {
                    "name": name,
                    "max_sdk_version": self._android_attr(element, "maxSdkVersion"),
                }
            )
        return permissions

    def _components(
        self,
        application: ET.Element | None,
        package_name: str,
    ) -> tuple[dict[str, list[dict[str, Any]]], list[dict[str, str]], str]:
        components: dict[str, list[dict[str, Any]]] = {
            "activities": [],
            "services": [],
            "receivers": [],
            "providers": [],
        }
        deep_links: list[dict[str, str]] = []
        main_activity = ""
        if application is None:
            return components, deep_links, main_activity

        for element in application:
            tag = self._local_name(element.tag)
            if tag not in self.COMPONENT_TAGS:
                continue
            raw_name = self._android_attr(element, "name")
            name = self._qualified_component_name(raw_name, package_name)
            filters = [self._intent_filter(item) for item in element if self._local_name(item.tag) == "intent-filter"]
            if tag in {"activity", "activity-alias"} and any(self._launcher_filter(item) for item in filters):
                main_activity = name or main_activity
            component = {
                "name": name,
                "exported": self._boolean_attr(element, "exported"),
                "permission": self._android_attr(element, "permission"),
                "intent_filters": filters,
            }
            if tag == "activity-alias":
                component["target_activity"] = self._qualified_component_name(
                    self._android_attr(element, "targetActivity"),
                    package_name,
                )
                components["activities"].append(component)
            else:
                components[self.COMPONENT_COLLECTIONS[tag]].append(component)
            deep_links.extend(self._deep_links(name, filters))
        return components, deep_links, main_activity

    def _intent_filter(self, element: ET.Element) -> dict[str, Any]:
        return {
            "actions": [
                self._android_attr(child, "name")
                for child in element
                if self._local_name(child.tag) == "action" and self._android_attr(child, "name")
            ],
            "categories": [
                self._android_attr(child, "name")
                for child in element
                if self._local_name(child.tag) == "category" and self._android_attr(child, "name")
            ],
            "data": [
                {
                    key: self._android_attr(child, android_key)
                    for key, android_key in (
                        ("scheme", "scheme"),
                        ("host", "host"),
                        ("port", "port"),
                        ("path", "path"),
                        ("path_prefix", "pathPrefix"),
                        ("path_pattern", "pathPattern"),
                        ("mime_type", "mimeType"),
                    )
                }
                for child in element
                if self._local_name(child.tag) == "data"
            ],
        }

    @staticmethod
    def _launcher_filter(intent_filter: dict[str, Any]) -> bool:
        return (
            "android.intent.action.MAIN" in intent_filter["actions"]
            and "android.intent.category.LAUNCHER" in intent_filter["categories"]
        )

    @staticmethod
    def _deep_links(component_name: str, filters: list[dict[str, Any]]) -> list[dict[str, str]]:
        links: list[dict[str, str]] = []
        for intent_filter in filters:
            for data in intent_filter["data"]:
                if not data.get("scheme") and not data.get("host"):
                    continue
                links.append({"component": component_name, **data})
        return links

    def _has_launcher_activity(self, manifest_path: Path) -> bool:
        try:
            root = ET.parse(manifest_path).getroot()
        except (ET.ParseError, OSError):
            return False
        application = root.find("application")
        if application is None:
            return False
        for component in application:
            if self._local_name(component.tag) not in {"activity", "activity-alias"}:
                continue
            for child in component:
                if self._local_name(child.tag) == "intent-filter" and self._launcher_filter(self._intent_filter(child)):
                    return True
        return False

    @staticmethod
    def _qualified_component_name(name: str, package_name: str) -> str:
        if not name:
            return ""
        if name.startswith("."):
            return f"{package_name}{name}" if package_name else name
        if "." not in name and package_name:
            return f"{package_name}.{name}"
        return name

    @staticmethod
    def _android_attr(element: ET.Element | None, name: str) -> str:
        if element is None:
            return ""
        return str(element.get(f"{{{ANDROID_NAMESPACE}}}{name}") or "").strip()

    @classmethod
    def _boolean_attr(cls, element: ET.Element | None, name: str) -> bool | None:
        value = cls._android_attr(element, name).lower()
        if value == "true":
            return True
        if value == "false":
            return False
        return None

    @staticmethod
    def _local_name(tag: str) -> str:
        return tag.rsplit("}", 1)[-1]

    @staticmethod
    def _relative(project_path: Path, path: Path | None) -> str:
        if path is None:
            return ""
        try:
            return path.relative_to(project_path).as_posix()
        except ValueError:
            return path.name
