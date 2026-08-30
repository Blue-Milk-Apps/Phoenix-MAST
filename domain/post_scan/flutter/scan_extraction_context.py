"""Normalized access to Flutter source scan outputs."""

from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Any


class FlutterScanExtractionContext:
    """Provide defensive typed views over persisted Flutter scan artifacts."""

    COMPONENT_KEYS = ("activities", "services", "receivers", "providers")

    def __init__(self, loaded_outputs: dict[str, Any]) -> None:
        self.loaded_outputs = loaded_outputs

    @property
    def scan_metadata(self) -> dict[str, Any]:
        return self._mapping(self.loaded_outputs.get("scan_metadata"))

    @property
    def source_metadata(self) -> dict[str, Any]:
        return self._mapping(self.loaded_outputs.get("source_metadata"))

    @property
    def extraction(self) -> dict[str, Any]:
        return self._mapping(self.source_metadata.get("extraction"))

    @property
    def project(self) -> dict[str, Any]:
        return self._mapping(self.source_metadata.get("project"))

    @property
    def identity(self) -> dict[str, Any]:
        return self._mapping(self.source_metadata.get("identity"))

    @property
    def sdk(self) -> dict[str, Any]:
        return self._mapping(self.source_metadata.get("sdk"))

    @property
    def platforms(self) -> dict[str, bool]:
        values = self._mapping(self.source_metadata.get("platforms"))
        return {str(name): value for name, value in values.items() if isinstance(value, bool)}

    @property
    def dependencies(self) -> dict[str, list[dict[str, Any]]]:
        values = self._mapping(self.source_metadata.get("dependencies"))
        return {key: self._mapping_list(values.get(key)) for key in ("direct", "development", "resolved")}

    @property
    def project_path(self) -> Path:
        value = self.first_non_empty(
            self.scan_metadata.get("project_path"),
            self.project.get("project_path"),
        )
        return Path(value)

    @property
    def warnings(self) -> list[str]:
        return self.string_list(self.extraction.get("warnings"))

    @property
    def source_metadata_assessed(self) -> bool:
        return isinstance(self.loaded_outputs.get("source_metadata"), dict)

    @property
    def android(self) -> dict[str, Any]:
        return self._mapping(self.source_metadata.get("android"))

    @property
    def android_available(self) -> bool:
        return self.android.get("available") is True

    @property
    def android_metadata(self) -> dict[str, Any]:
        return self._mapping(self.android.get("metadata"))

    @property
    def android_metadata_assessed(self) -> bool:
        return self.android_available and isinstance(self.android.get("metadata"), dict)

    @property
    def android_identity(self) -> dict[str, Any]:
        return self._mapping(self.android_metadata.get("identity"))

    @property
    def android_application(self) -> dict[str, Any]:
        return self._mapping(self.android_metadata.get("application"))

    @property
    def android_permissions(self) -> list[dict[str, Any]]:
        return self._mapping_list(self.android_metadata.get("permissions"))

    @property
    def android_components(self) -> dict[str, list[dict[str, Any]]]:
        values = self._mapping(self.android_metadata.get("components"))
        return {key: self._mapping_list(values.get(key)) for key in self.COMPONENT_KEYS}

    @property
    def android_deep_links(self) -> list[dict[str, Any]]:
        return self._mapping_list(self.android_metadata.get("deep_links"))

    @property
    def ios(self) -> dict[str, Any]:
        return self._mapping(self.source_metadata.get("ios"))

    @property
    def ios_available(self) -> bool:
        return self.ios.get("available") is True

    @property
    def ios_metadata(self) -> dict[str, Any]:
        return self._mapping(self.ios.get("metadata"))

    @property
    def ios_metadata_assessed(self) -> bool:
        return self.ios_available and isinstance(self.ios.get("metadata"), dict)

    @property
    def ios_identity(self) -> dict[str, Any]:
        return self._mapping(self.ios_metadata.get("identity"))

    @property
    def ios_permissions(self) -> list[dict[str, Any]]:
        return self._mapping_list(self.ios_metadata.get("permissions"))

    @property
    def ios_app_transport_security(self) -> dict[str, Any]:
        return self._mapping(self.ios_metadata.get("app_transport_security"))

    @property
    def ios_url_schemes(self) -> dict[str, Any]:
        return self._mapping(self.ios_metadata.get("url_schemes"))

    @property
    def ios_background_modes(self) -> list[str]:
        return self.string_list(self.ios_metadata.get("background_modes"))

    @property
    def ios_entitlements(self) -> list[dict[str, Any]]:
        return self._mapping_list(self.ios_metadata.get("entitlements"))

    @property
    def ios_privacy_manifests(self) -> list[dict[str, Any]]:
        return self._mapping_list(self.ios_metadata.get("privacy_manifests"))

    @property
    def plist_outputs(self) -> dict[str, dict[str, Any]]:
        values = self._mapping(self.loaded_outputs.get("plist_outputs"))
        return {str(path): document for path, document in values.items() if isinstance(document, dict)}

    @property
    def plist_index(self) -> dict[str, Any]:
        return self._mapping(self.loaded_outputs.get("plist_index"))

    @property
    def plist_index_entries(self) -> list[dict[str, Any]]:
        return self._mapping_list(self.plist_index.get("plists"))

    @property
    def plist_assessed(self) -> bool:
        raw_index = self.loaded_outputs.get("plist_index")
        return isinstance(raw_index, dict) and isinstance(raw_index.get("plists"), list)

    def plist_outputs_for_role(self, role: str) -> dict[str, dict[str, Any]]:
        paths = {
            self.first_non_empty(entry.get("output_path"))
            for entry in self.plist_index_entries
            if entry.get("role") == role
        }
        paths.discard("")
        return {path: document for path, document in self.plist_outputs.items() if path in paths}

    @property
    def opengrep(self) -> dict[str, Any]:
        return self._mapping(self.loaded_outputs.get("opengrep"))

    @property
    def opengrep_results(self) -> list[dict[str, Any]]:
        return self._mapping_list(self.opengrep.get("results"))

    @property
    def opengrep_scopes(self) -> dict[str, dict[str, Any]]:
        metadata = self._mapping(self.opengrep.get("scan_metadata"))
        scopes = self._mapping(metadata.get("scopes"))
        return {str(scope): value for scope, value in scopes.items() if isinstance(value, dict)}

    def opengrep_scope(self, scope: str) -> dict[str, Any]:
        return self.opengrep_scopes.get(scope, {})

    def opengrep_scope_completed(self, scope: str) -> bool:
        return self.opengrep_scope(scope).get("status") == "success"

    def opengrep_scope_assessed(self, scope: str) -> bool:
        scope_metadata = self.opengrep_scope(scope)
        return scope_metadata.get("status") == "success" and isinstance(scope_metadata.get("configured_rule_ids"), list)

    def opengrep_configured_rule_ids(self, scope: str) -> frozenset[str]:
        configured = self.opengrep_scope(scope).get("configured_rule_ids")
        return frozenset(self.string_list(configured))

    def opengrep_results_for_scope(self, scope: str) -> list[dict[str, Any]]:
        return [result for result in self.opengrep_results if self._opengrep_result_scope(result) == scope]

    @property
    def gitleaks_assessed(self) -> bool:
        return isinstance(self._known_scanner_output("gitleaks_outputs", "gitleaks_report.json"), list)

    @property
    def trufflehog_assessed(self) -> bool:
        return isinstance(self._known_scanner_output("trufflehog_outputs", "trufflehog_results.json"), list)

    @property
    def gitleaks_findings(self) -> list[dict[str, Any]]:
        return self._scanner_findings("gitleaks_outputs", ("findings", "results"))

    @property
    def trufflehog_findings(self) -> list[dict[str, Any]]:
        return self._scanner_findings("trufflehog_outputs", ("findings", "results"))

    @property
    def syft_packages(self) -> list[tuple[str, str, str]]:
        packages: list[tuple[str, str, str]] = []
        for output_path, content in self._scanner_outputs("syft_outputs").items():
            if not isinstance(content, dict):
                continue
            for collection_name in ("components", "artifacts"):
                for package in content.get(collection_name) or []:
                    if not isinstance(package, dict):
                        continue
                    name = self.first_non_empty(package.get("name"))
                    version = self.first_non_empty(package.get("version"))
                    if name:
                        packages.append((output_path, name, version))
        return list(dict.fromkeys(packages))

    @property
    def syft_assessed(self) -> bool:
        for content in self._scanner_outputs("syft_outputs").values():
            if not isinstance(content, dict) or content.get("success") is False:
                continue
            if isinstance(content.get("components"), list) or isinstance(content.get("artifacts"), list):
                return True
        return False

    @property
    def scan_date(self) -> str:
        explicit = self.first_non_empty(self.scan_metadata.get("scan_date"))
        if explicit:
            return explicit
        output_path = Path(str(self.loaded_outputs.get("scan_output_path", "")))
        try:
            date_part, time_part = output_path.name.rsplit("_", 2)[-2:]
            parsed = datetime.strptime(f"{date_part}_{time_part}", "%Y-%m-%d_%H-%M-%S")
            return parsed.strftime("%Y-%m-%d %H:%M:%S")
        except (ValueError, IndexError):
            return ""

    def _scanner_findings(
        self,
        output_key: str,
        collection_names: tuple[str, ...],
    ) -> list[dict[str, Any]]:
        findings: list[dict[str, Any]] = []
        for content in self._scanner_outputs(output_key).values():
            if isinstance(content, list):
                findings.extend(item for item in content if isinstance(item, dict))
                continue
            if not isinstance(content, dict):
                continue
            for collection_name in collection_names:
                collection = content.get(collection_name)
                if isinstance(collection, list):
                    findings.extend(item for item in collection if isinstance(item, dict))
                    break
        return findings

    def _scanner_outputs(self, key: str) -> dict[str, Any]:
        return self._mapping(self.loaded_outputs.get(key))

    def _known_scanner_output(self, key: str, filename: str) -> Any:
        return self._scanner_outputs(key).get(filename)

    @staticmethod
    def _opengrep_result_scope(result: dict[str, Any]) -> str:
        explicit = str(result.get("phoenix_scope", "")).strip()
        if explicit:
            return explicit
        rule_id = str(result.get("check_id", "")).strip()
        if rule_id.startswith("flutter."):
            return "flutter"
        if rule_id.startswith("android."):
            return "android"
        return ""

    @staticmethod
    def _mapping(value: object) -> dict[str, Any]:
        return value if isinstance(value, dict) else {}

    @staticmethod
    def _mapping_list(value: object) -> list[dict[str, Any]]:
        if not isinstance(value, list):
            return []
        return [item for item in value if isinstance(item, dict)]

    @staticmethod
    def first_non_empty(*values: object) -> str:
        for value in values:
            text = str(value or "").strip()
            if text:
                return text
        return ""

    @staticmethod
    def string_list(value: object) -> list[str]:
        if not isinstance(value, list):
            return []
        return list(dict.fromkeys(str(item).strip() for item in value if str(item).strip()))
