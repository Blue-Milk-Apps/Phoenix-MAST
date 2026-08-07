"""Native iOS source scan-output loader for post-scan processing."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from ports.post_scan.scan_output_loader_port import ScanOutputLoaderPort


class NativeIOSScanOutputLoader(ScanOutputLoaderPort):
    """Load native iOS source scan outputs needed by post-scan processing."""

    def load(self, scan_output_path: Path) -> dict[str, Any]:
        root = Path(scan_output_path)
        return {
            "scan_output_path": str(root),
            "scan_metadata": self._load_json(root / "scan_metadata.json"),
            "opengrep": self._load_json(root / "opengrep_source" / "opengrep_results.json"),
            "plist_outputs": self._load_json_documents(
                root / "plist_source",
                exclude={"scan_index.json"},
            ),
            "plist_index": self._load_json(root / "plist_source" / "scan_index.json"),
            "trufflehog_outputs": self._load_optional_outputs(root / "trufflehog"),
            "gitleaks_outputs": self._load_optional_outputs(root / "gitleaks"),
            "syft_outputs": self._load_optional_outputs(root / "syft"),
        }

    @staticmethod
    def _load_json(path: Path) -> dict[str, Any] | None:
        if not path.is_file():
            return None

        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            return None

    @classmethod
    def _load_json_documents(
        cls,
        root: Path,
        *,
        exclude: set[str] | None = None,
    ) -> dict[str, dict[str, Any] | None]:
        if not root.is_dir():
            return {}

        outputs: dict[str, dict[str, Any] | None] = {}
        excluded = exclude or set()
        for path in sorted(root.rglob("*.json")):
            relative_path = path.relative_to(root).as_posix()
            if relative_path in excluded:
                continue
            outputs[relative_path] = cls._load_json(path)
        return outputs

    @classmethod
    def _load_optional_outputs(cls, root: Path, pattern: str = "*") -> dict[str, Any]:
        if not root.is_dir():
            return {}

        outputs: dict[str, Any] = {}
        for path in sorted(root.rglob(pattern)):
            if not path.is_file():
                continue
            relative_path = path.relative_to(root).as_posix()
            if path.suffix.lower() == ".json":
                outputs[relative_path] = cls._load_json(path)
            else:
                outputs[relative_path] = path.read_text(
                    encoding="utf-8",
                    errors="ignore",
                )
        return outputs
