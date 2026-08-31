"""Flutter source scan-output loader for post-scan processing."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from ports.post_scan.scan_output_loader_port import ScanOutputLoaderPort


class FlutterScanOutputLoader(ScanOutputLoaderPort):
    """Load persisted Flutter and embedded-platform source scan artifacts."""

    def load(self, scan_output_path: Path) -> dict[str, Any]:
        root = Path(scan_output_path)
        return {
            "scan_output_path": str(root),
            "scan_metadata": self._load_json(root / "scan_metadata.json"),
            "source_metadata": self._load_json(root / "flutter_source_metadata" / "project_metadata.json"),
            "opengrep": self._load_json(root / "opengrep_source" / "opengrep_results.json"),
            "plist_outputs": self._load_json_documents(
                root / "plist_source",
                exclude={"scan_index.json"},
            ),
            "plist_index": self._load_json(root / "plist_source" / "scan_index.json"),
            "trufflehog_outputs": self._load_known_json(root / "trufflehog" / "trufflehog_results.json"),
            "gitleaks_outputs": self._load_known_json(root / "gitleaks" / "gitleaks_report.json"),
            "syft_outputs": self._load_known_json(root / "syft" / "sbom.json"),
        }

    @staticmethod
    def _load_json(path: Path) -> Any | None:
        if not path.is_file():
            return None
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return None

    @classmethod
    def _load_json_documents(
        cls,
        root: Path,
        *,
        exclude: set[str] | None = None,
    ) -> dict[str, Any | None]:
        if not root.is_dir():
            return {}

        excluded = exclude or set()
        outputs: dict[str, Any | None] = {}
        for path in sorted(root.rglob("*.json")):
            relative_path = path.relative_to(root).as_posix()
            if relative_path in excluded:
                continue
            outputs[relative_path] = cls._load_json(path)
        return outputs

    @classmethod
    def _load_known_json(cls, path: Path) -> dict[str, Any | None]:
        if not path.is_file():
            return {}
        return {path.name: cls._load_json(path)}
