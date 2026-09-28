"""Build Android binary file metadata for post-scan reports."""

from __future__ import annotations

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

        file_hashes = scan_metadata.get("file_info") or {}
        size_bytes = file_hashes.get("size", apk_details.get("size_bytes"))

        self.filename = first_non_empty(
            apk_details.get("file_name"),
            androguard_metadata.get("file_name"),
            Path(str(scan_metadata.get("project_path", ""))).name,
        )
        self.size = first_non_empty(size_bytes)
        self.md5 = first_non_empty(file_hashes.get("md5"))
        self.sha1 = first_non_empty(file_hashes.get("sha1"))
        self.sha256 = first_non_empty(file_hashes.get("sha256"), apk_details.get("sha256"))
