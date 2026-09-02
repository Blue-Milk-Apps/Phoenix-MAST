"""React Native source scan-output loader for post-scan processing."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from ports.post_scan.scan_output_loader_port import ScanOutputLoaderPort


class ReactNativeScanOutputLoader(ScanOutputLoaderPort):
    """Load persisted React Native and embedded-platform source scan artifacts."""

    SCAN_METADATA_PATH = Path("scan_metadata.json")
    SOURCE_METADATA_PATH = Path("react_native_metadata/project_metadata.json")
    OPENGREP_PATH = Path("opengrep_source/opengrep_results.json")
    PLIST_ROOT = Path("plist_source")
    PLIST_INDEX_PATH = PLIST_ROOT / "scan_index.json"
    TRUFFLEHOG_PATH = Path("trufflehog/trufflehog_results.json")
    GITLEAKS_PATH = Path("gitleaks/gitleaks_report.json")
    SYFT_PATH = Path("syft/sbom.json")

    def load(self, scan_output_path: Path) -> dict[str, Any]:
        root = Path(scan_output_path)
        return {
            "scan_output_path": str(root),
            "scan_metadata": self._load_json(root / self.SCAN_METADATA_PATH, scan_root=root),
            "source_metadata": self._load_json(root / self.SOURCE_METADATA_PATH, scan_root=root),
            "opengrep": self._load_json(root / self.OPENGREP_PATH, scan_root=root),
            "plist_outputs": self._load_json_documents(
                root / self.PLIST_ROOT,
                exclude={self.PLIST_INDEX_PATH.name},
                scan_root=root,
            ),
            "plist_index": self._load_json(root / self.PLIST_INDEX_PATH, scan_root=root),
            "trufflehog_outputs": self._load_known_json(root / self.TRUFFLEHOG_PATH, scan_root=root),
            "gitleaks_outputs": self._load_known_json(root / self.GITLEAKS_PATH, scan_root=root),
            "syft_outputs": self._load_known_json(root / self.SYFT_PATH, scan_root=root),
        }

    @classmethod
    def _load_json(cls, path: Path, *, scan_root: Path) -> Any | None:
        if not path.is_file() or not cls._is_within_root(path, scan_root):
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
        scan_root: Path,
    ) -> dict[str, Any | None]:
        if not root.is_dir() or not cls._is_within_root(root, scan_root):
            return {}

        excluded = exclude or set()
        outputs: dict[str, Any | None] = {}
        for path in sorted(root.rglob("*.json")):
            if not path.is_file() or not cls._is_within_root(path, scan_root):
                continue
            relative_path = path.relative_to(root).as_posix()
            if relative_path in excluded:
                continue
            outputs[relative_path] = cls._load_json(path, scan_root=scan_root)
        return outputs

    @classmethod
    def _load_known_json(cls, path: Path, *, scan_root: Path) -> dict[str, Any | None]:
        if not path.is_file() or not cls._is_within_root(path, scan_root):
            return {}
        return {path.name: cls._load_json(path, scan_root=scan_root)}

    @staticmethod
    def _is_within_root(path: Path, root: Path) -> bool:
        try:
            path.resolve().relative_to(root.resolve())
        except (OSError, ValueError):
            return False
        return True
