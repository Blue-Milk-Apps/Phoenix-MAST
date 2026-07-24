"""Build default iOS file info section for post-scan reports."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from domain.post_scan.utilities import first_non_empty


@dataclass
class IOSFileInfo:
    filename: str
    size: str
    md5: str
    sha1: str
    sha256: str

    def __init__(self, loaded_outputs: dict[str, Any]) -> None:
        scan_metadata = loaded_outputs.get("scan_metadata") or {}
        file_path = self._existing_file_path(scan_metadata.get("project_path"))
        file_hashes = self._hash_file(file_path) if file_path else {}

        self.filename = first_non_empty(Path(str(scan_metadata.get("project_path", ""))).name)
        self.size = first_non_empty(file_path.stat().st_size if file_path else "")
        self.md5 = first_non_empty(file_hashes.get("md5"))
        self.sha1 = first_non_empty(file_hashes.get("sha1"))
        self.sha256 = first_non_empty(file_hashes.get("sha256"))

    @staticmethod
    def _existing_file_path(candidate: object) -> Path | None:
        path = Path(str(candidate or "").strip())
        return path if path.is_file() else None

    @staticmethod
    def _hash_file(path: Path) -> dict[str, str]:
        md5 = hashlib.md5()  # noqa: S324 - report metadata only
        sha1 = hashlib.sha1()  # noqa: S324 - report metadata only
        sha256 = hashlib.sha256()

        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(8192), b""):
                md5.update(chunk)
                sha1.update(chunk)
                sha256.update(chunk)

        return {"md5": md5.hexdigest(), "sha1": sha1.hexdigest(), "sha256": sha256.hexdigest()}
