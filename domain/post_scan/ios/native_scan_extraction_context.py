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
    def primary_app_meta(self) -> dict[str, Any]:
        for document in self.plist_outputs.values():
            app_meta = document.get("app_meta")
            if isinstance(app_meta, dict) and app_meta:
                return app_meta
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
