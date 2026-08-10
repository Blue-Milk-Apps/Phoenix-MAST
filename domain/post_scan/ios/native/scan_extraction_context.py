"""Normalized access to native iOS source scan outputs."""

from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Any


class NativeIOSScanExtractionContext:
    """Provide typed views over persisted native iOS source artifacts."""

    def __init__(self, loaded_outputs: dict[str, Any]) -> None:
        self.loaded_outputs = loaded_outputs

    @property
    def scan_metadata(self) -> dict[str, Any]:
        value = self.loaded_outputs.get("scan_metadata") or {}
        return value if isinstance(value, dict) else {}

    @property
    def project_path(self) -> Path:
        return Path(str(self.scan_metadata.get("project_path", "")))

    @property
    def plist_outputs(self) -> dict[str, dict[str, Any]]:
        outputs = self.loaded_outputs.get("plist_outputs") or {}
        if not isinstance(outputs, dict):
            return {}
        return {path: document for path, document in outputs.items() if isinstance(document, dict)}

    @property
    def plist_index_entries(self) -> list[dict[str, Any]]:
        index = self.loaded_outputs.get("plist_index") or {}
        entries = index.get("plists") if isinstance(index, dict) else None
        if not isinstance(entries, list):
            return []
        return [entry for entry in entries if isinstance(entry, dict)]

    @property
    def entitlement_outputs(self) -> dict[str, dict[str, Any]]:
        return self._outputs_for_role("entitlements")

    @property
    def privacy_manifest_outputs(self) -> dict[str, dict[str, Any]]:
        return self._outputs_for_role("privacy_manifest")

    @property
    def primary_app_meta(self) -> dict[str, Any]:
        indexed_app_paths = {
            str(entry.get("output_path", ""))
            for entry in self.plist_index_entries
            if entry.get("role") == "app" and entry.get("output_path")
        }
        candidates = [
            (path, app_meta)
            for path, document in self.plist_outputs.items()
            if (not indexed_app_paths or path in indexed_app_paths)
            and isinstance((app_meta := document.get("app_meta")), dict)
            and app_meta
        ]
        if candidates:
            return min(candidates, key=self._primary_app_sort_key)[1]
        return {}

    @property
    def opengrep_results(self) -> list[dict[str, Any]]:
        opengrep = self.loaded_outputs.get("opengrep") or {}
        results = opengrep.get("results") if isinstance(opengrep, dict) else None
        if not isinstance(results, list):
            return []
        return [result for result in results if isinstance(result, dict)]

    @property
    def syft_packages(self) -> list[tuple[str, str, str]]:
        packages: list[tuple[str, str, str]] = []
        outputs = self.loaded_outputs.get("syft_outputs") or {}
        if not isinstance(outputs, dict):
            return packages
        for path, content in outputs.items():
            if not isinstance(content, dict):
                continue
            for collection_name in ("components", "artifacts"):
                for package in content.get(collection_name) or []:
                    if not isinstance(package, dict):
                        continue
                    name = str(package.get("name", "")).strip()
                    version = str(package.get("version", "")).strip()
                    if name:
                        packages.append((str(path), name, version))
        return packages

    @property
    def scan_date(self) -> str:
        explicit = str(self.scan_metadata.get("scan_date", "")).strip()
        if explicit:
            return explicit
        output_path = Path(str(self.loaded_outputs.get("scan_output_path", "")))
        try:
            date_part, time_part = output_path.name.rsplit("_", 2)[-2:]
            return datetime.strptime(f"{date_part}_{time_part}", "%Y-%m-%d_%H-%M-%S").strftime("%Y-%m-%d %H:%M:%S")
        except (ValueError, IndexError):
            return ""

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

    def _outputs_for_role(self, role: str) -> dict[str, dict[str, Any]]:
        paths = {
            str(entry.get("output_path", ""))
            for entry in self.plist_index_entries
            if entry.get("role") == role and entry.get("output_path")
        }
        return {path: document for path, document in self.plist_outputs.items() if path in paths}

    def _primary_app_sort_key(self, candidate: tuple[str, dict[str, Any]]) -> tuple[int, int, int, str]:
        path, app_meta = candidate
        lowered_parts = {part.lower() for part in Path(path).parts}
        dependency_parts = {
            ".build",
            "carthage",
            "deriveddata",
            "frameworks",
            "pods",
            "vendor",
        }
        dependency_penalty = int(bool(lowered_parts & dependency_parts) or ".framework" in path.lower())

        project_name = self._normalized_name(self.project_path.stem)
        candidate_names = " ".join(
            (
                path,
                str(app_meta.get("bundle_identifier", "")),
                str(app_meta.get("bundle_name", "")),
                str(app_meta.get("display_name", "")),
            )
        )
        project_affinity_penalty = int(
            bool(project_name) and project_name not in self._normalized_name(candidate_names)
        )
        return dependency_penalty, project_affinity_penalty, len(Path(path).parts), path.lower()

    @staticmethod
    def _normalized_name(value: str) -> str:
        return "".join(character for character in value.lower() if character.isalnum())
