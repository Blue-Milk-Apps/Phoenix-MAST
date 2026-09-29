"""Shared artifact reads with explicit diagnostics for unreadable evidence."""

import json
import warnings
from pathlib import Path
from typing import Any

from ports.post_scan.scan_output_loader_port import ScanOutputLoaderPort


class ArtifactLoader(ScanOutputLoaderPort):
    @staticmethod
    def _load_json(path: Path) -> Any:
        if not path.is_file():
            return None
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            warnings.warn(f"Unreadable tool artifact {path}: {exc}", stacklevel=2)
            return None

    @classmethod
    def _load_binary_opengrep(cls, root: Path) -> Any:
        path = root / "opengrep_binary" / "opengrep_results.json"
        if not path.exists():
            # Older binary scans used the source artifact directory too.
            path = root / "opengrep_source" / "opengrep_results.json"
        return cls._load_json(path)

    @classmethod
    def _load_known_json(cls, path: Path) -> dict[str, Any]:
        return {path.name: cls._load_json(path)} if path.is_file() else {}

    @classmethod
    def _load_json_documents(cls, root: Path, *, exclude: set[str] | None = None) -> dict[str, Any]:
        excluded = exclude or set()
        return {
            path.relative_to(root).as_posix(): cls._load_json(path)
            for path in sorted(root.rglob("*.json"))
            if path.is_file() and path.relative_to(root).as_posix() not in excluded
        }

    @staticmethod
    def _load_text_outputs(root: Path, pattern: str = "*.txt") -> dict[str, str]:
        return {
            path.relative_to(root).as_posix(): path.read_text(encoding="utf-8", errors="replace")
            for path in sorted(root.rglob(pattern))
            if path.is_file()
        }
