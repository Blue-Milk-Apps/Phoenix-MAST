"""Defensive access to React Native source scan artifacts."""

from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Any


class ReactNativeScanExtractionContext:
    def __init__(self, loaded_outputs: dict[str, Any]) -> None:
        self.loaded_outputs = loaded_outputs

    @property
    def scan_metadata(self) -> dict[str, Any]:
        return self.mapping(self.loaded_outputs.get("scan_metadata"))

    @property
    def source_metadata(self) -> dict[str, Any]:
        return self.mapping(self.loaded_outputs.get("source_metadata"))

    @property
    def project(self) -> dict[str, Any]:
        return self.mapping(self.source_metadata.get("project"))

    @property
    def identity(self) -> dict[str, Any]:
        return self.mapping(self.source_metadata.get("identity"))

    @property
    def runtime(self) -> dict[str, Any]:
        return self.mapping(self.source_metadata.get("runtime"))

    @property
    def platforms(self) -> dict[str, bool]:
        values = self.mapping(self.source_metadata.get("platforms"))
        return {key: values.get(key) is True for key in ("android", "ios")}

    @property
    def dependencies(self) -> dict[str, list[dict[str, Any]]]:
        values = self.mapping(self.source_metadata.get("dependencies"))
        return {key: self.mapping_list(values.get(key)) for key in ("declared", "resolved")}

    @property
    def android(self) -> dict[str, Any]:
        return self.mapping(self.source_metadata.get("android"))

    @property
    def android_metadata(self) -> dict[str, Any]:
        return self.mapping(self.android.get("metadata"))

    @property
    def ios(self) -> dict[str, Any]:
        return self.mapping(self.source_metadata.get("ios"))

    @property
    def ios_metadata(self) -> dict[str, Any]:
        return self.mapping(self.ios.get("metadata"))

    @property
    def warnings(self) -> list[str]:
        return self.string_list(self.mapping(self.source_metadata.get("extraction")).get("warnings"))

    @property
    def project_path(self) -> Path:
        return Path(self.first_non_empty(self.scan_metadata.get("project_path"), self.project.get("project_path")))

    @property
    def opengrep(self) -> dict[str, Any]:
        return self.mapping(self.loaded_outputs.get("opengrep"))

    @property
    def opengrep_results(self) -> list[dict[str, Any]]:
        return self.mapping_list(self.opengrep.get("results"))

    @property
    def opengrep_scopes(self) -> dict[str, dict[str, Any]]:
        scopes = self.mapping(self.mapping(self.opengrep.get("scan_metadata")).get("scopes"))
        return {str(key): value for key, value in scopes.items() if isinstance(value, dict)}

    def opengrep_scope(self, scope: str) -> dict[str, Any]:
        return self.opengrep_scopes.get(scope, {})

    def opengrep_scope_applicable(self, scope: str) -> bool:
        metadata = self.opengrep_scope(scope)
        return metadata.get("applicable") is True or metadata.get("status") in {"success", "failed"}

    def opengrep_scope_assessed(self, scope: str, rule_ids: frozenset[str]) -> bool:
        metadata = self.opengrep_scope(scope)
        configured = metadata.get("configured_rule_ids")
        return (
            metadata.get("status") == "success"
            and isinstance(configured, list)
            and set(rule_ids) <= set(self.string_list(configured))
        )

    def opengrep_results_for_scope(self, scope: str) -> list[dict[str, Any]]:
        return [item for item in self.opengrep_results if self.first_non_empty(item.get("phoenix_scope")) == scope]

    @property
    def gitleaks_assessed(self) -> bool:
        return isinstance(self._known_output("gitleaks_outputs", "gitleaks_report.json"), list)

    @property
    def trufflehog_assessed(self) -> bool:
        return isinstance(self._known_output("trufflehog_outputs", "trufflehog_results.json"), list)

    @property
    def gitleaks_findings(self) -> list[dict[str, Any]]:
        return self._findings("gitleaks_outputs", "gitleaks_report.json")

    @property
    def trufflehog_findings(self) -> list[dict[str, Any]]:
        return self._findings("trufflehog_outputs", "trufflehog_results.json")

    @property
    def syft_packages(self) -> list[dict[str, str]]:
        output = self._known_output("syft_outputs", "sbom.json")
        if not isinstance(output, dict):
            return []
        packages: list[dict[str, str]] = []
        for key in ("artifacts", "components"):
            for item in output.get(key, []) if isinstance(output.get(key), list) else []:
                if isinstance(item, dict) and self.first_non_empty(item.get("name")):
                    packages.append(
                        {
                            "name": self.first_non_empty(item.get("name")),
                            "version": self.first_non_empty(item.get("version")),
                        }
                    )
        return packages

    @property
    def syft_assessed(self) -> bool:
        output = self._known_output("syft_outputs", "sbom.json")
        return isinstance(output, dict) and any(
            isinstance(output.get(key), list) for key in ("artifacts", "components")
        )

    @property
    def scan_date(self) -> str:
        explicit = self.first_non_empty(self.scan_metadata.get("scan_date"))
        if explicit:
            return explicit
        name = Path(str(self.loaded_outputs.get("scan_output_path", ""))).name
        try:
            date, time = name.rsplit("_", 2)[-2:]
            return datetime.strptime(f"{date}_{time}", "%Y-%m-%d_%H-%M-%S").strftime("%Y-%m-%d %H:%M:%S")
        except (ValueError, IndexError):
            return ""

    def _known_output(self, group: str, name: str) -> Any:
        return self.mapping(self.loaded_outputs.get(group)).get(name)

    def _findings(self, group: str, name: str) -> list[dict[str, Any]]:
        output = self._known_output(group, name)
        if isinstance(output, list):
            return [item for item in output if isinstance(item, dict)]
        if isinstance(output, dict):
            for key in ("findings", "results"):
                if isinstance(output.get(key), list):
                    return [item for item in output[key] if isinstance(item, dict)]
        return []

    @staticmethod
    def mapping(value: object) -> dict[str, Any]:
        return value if isinstance(value, dict) else {}

    @classmethod
    def mapping_list(cls, value: object) -> list[dict[str, Any]]:
        return [item for item in value if isinstance(item, dict)] if isinstance(value, list) else []

    @staticmethod
    def string_list(value: object) -> list[str]:
        return [str(item).strip() for item in value if str(item).strip()] if isinstance(value, list) else []

    @staticmethod
    def first_non_empty(*values: object) -> str:
        return next((str(value).strip() for value in values if value is not None and str(value).strip()), "")
