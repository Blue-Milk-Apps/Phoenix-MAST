"""Build default iOS file info section for post-scan reports."""

from __future__ import annotations

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
        file_hashes = scan_metadata.get("file_info") or {}

        self.filename = first_non_empty(
            Path(str(scan_metadata.get("project_path", ""))).name,
            self._filename_fallback(loaded_outputs),
        )
        self.size = first_non_empty(file_hashes.get("size"))
        self.md5 = first_non_empty(file_hashes.get("md5"))
        self.sha1 = first_non_empty(file_hashes.get("sha1"))
        self.sha256 = first_non_empty(file_hashes.get("sha256"))

    @classmethod
    def _filename_fallback(cls, loaded_outputs: dict[str, Any]) -> str:
        for document in cls._primary_documents(loaded_outputs.get("ipsw_outputs")):
            binary = document.get("binary")
            if not isinstance(binary, dict):
                continue
            name = first_non_empty(binary.get("name"))
            if name:
                return name

        for document in cls._primary_documents(loaded_outputs.get("lief_outputs")):
            binary = document.get("binary")
            if not isinstance(binary, dict):
                continue
            name = first_non_empty(binary.get("name"))
            if name:
                return name

        return ""

    @staticmethod
    def _primary_documents(documents: Any) -> list[dict[str, Any]]:
        if not isinstance(documents, dict):
            return []

        typed_documents = [document for document in documents.values() if isinstance(document, dict)]
        if not typed_documents:
            return []

        primary = [
            document
            for document in typed_documents
            if str(((document.get("binary") or {}).get("kind", ""))).strip().lower() == "main"
        ]
        return primary or typed_documents
