"""Normalized access to native Android source scan outputs."""

from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Any


class NativeAndroidScanExtractionContext:
    """Provide typed views over persisted native Android source artifacts."""

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
    def application(self) -> dict[str, Any]:
        return self._mapping(self.source_metadata.get("application"))

    @property
    def project_path(self) -> Path:
        value = self.first_non_empty(
            self.scan_metadata.get("project_path"),
            self.project.get("project_path"),
        )
        return Path(value)

    @property
    def module_path(self) -> Path:
        value = self.first_non_empty(self.project.get("module_path"))
        if not value:
            return self.project_path
        path = Path(value)
        return path if path.is_absolute() else self.project_path / path

    @property
    def permissions(self) -> list[dict[str, Any]]:
        return self._mapping_list(self.source_metadata.get("permissions"))

    @property
    def components(self) -> dict[str, list[dict[str, Any]]]:
        value = self._mapping(self.source_metadata.get("components"))
        return {key: self._mapping_list(value.get(key)) for key in self.COMPONENT_KEYS}

    @property
    def deep_links(self) -> list[dict[str, Any]]:
        return self._mapping_list(self.source_metadata.get("deep_links"))

    @property
    def warnings(self) -> list[str]:
        return self.string_list(self.extraction.get("warnings"))

    @property
    def manifest_permissions_assessed(self) -> bool:
        return isinstance(self.source_metadata.get("permissions"), list)

    @property
    def opengrep_assessed(self) -> bool:
        opengrep = self.loaded_outputs.get("opengrep")
        return (
            isinstance(opengrep, dict)
            and opengrep.get("success") is not False
            and isinstance(opengrep.get("results"), list)
        )

    @property
    def gitleaks_assessed(self) -> bool:
        return isinstance(self._known_scanner_output("gitleaks_outputs", "gitleaks_report.json"), list)

    @property
    def trufflehog_assessed(self) -> bool:
        return isinstance(self._known_scanner_output("trufflehog_outputs", "trufflehog_results.json"), list)

    @property
    def opengrep_results(self) -> list[dict[str, Any]]:
        opengrep = self._mapping(self.loaded_outputs.get("opengrep"))
        return self._mapping_list(opengrep.get("results"))

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
                    name = str(package.get("name", "")).strip()
                    version = str(package.get("version", "")).strip()
                    if name:
                        packages.append((output_path, name, version))
        return list(dict.fromkeys(packages))

    @property
    def scan_date(self) -> str:
        explicit = str(self.scan_metadata.get("scan_date", "")).strip()
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
    def _mapping(value: Any) -> dict[str, Any]:
        return value if isinstance(value, dict) else {}

    @staticmethod
    def _mapping_list(value: Any) -> list[dict[str, Any]]:
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
    def string_list(value: Any) -> list[str]:
        if not isinstance(value, list):
            return []
        return list(dict.fromkeys(str(item).strip() for item in value if str(item).strip()))
