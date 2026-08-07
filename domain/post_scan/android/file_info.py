"""Build Android binary file metadata for post-scan reports."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from domain.post_scan.utilities import first_non_empty


@dataclass
class FileInfo:
    filename: str
    size: str
    md5: str
    sha1: str
    sha256: str

    def __init__(self, loaded_outputs: dict[str, Any]) -> None:
        scan_metadata = loaded_outputs.get("scan_metadata") or {}
        androguard_metadata = loaded_outputs.get("androguard_metadata") or {}
        signing_evidence = loaded_outputs.get("apksigner_signing_evidence") or {}
        apk_details = signing_evidence.get("apk") or {}

        file_path = self._existing_file_path(
            scan_metadata.get("project_path"),
            androguard_metadata.get("apk_path"),
        )
        file_hashes = self._hash_file(file_path) if file_path else {}
        size_bytes = apk_details.get("size_bytes")
        if size_bytes in (None, "") and file_path is not None:
            size_bytes = file_path.stat().st_size

        self.filename = first_non_empty(
            apk_details.get("file_name"),
            androguard_metadata.get("file_name"),
            Path(str(scan_metadata.get("project_path", ""))).name,
        )
        self.size = first_non_empty(size_bytes)
        self.md5 = first_non_empty(file_hashes.get("md5"))
        self.sha1 = first_non_empty(file_hashes.get("sha1"))
        self.sha256 = first_non_empty(file_hashes.get("sha256"), apk_details.get("sha256"))

    @staticmethod
    def _existing_file_path(*candidates: object) -> Path | None:
        for candidate in candidates:
            path = Path(str(candidate or "").strip())
            if path.is_file():
                return path
        return None

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
