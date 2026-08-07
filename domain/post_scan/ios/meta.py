"""Build the iOS binary meta section for post-scan reports."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

from domain.post_scan.utilities import first_non_empty


@dataclass
class IOSProjectMetadata:
    app_display_name: str
    file_name: str
    package_name: str
    version_code: str
    version_name: str
    main_executable_name: str
    main_binary_path: str
    architectures: list[str] = field(default_factory=list)
    macho_file_type: str = ""
    imported_function_count: str = ""
    linked_libraries: list[str] = field(default_factory=list)
    minimum_os_version: str = ""
    code_signature_present: str = ""
    has_rpath: str = ""

    @classmethod
    def from_loaded_outputs(cls, loaded_outputs: dict[str, Any]) -> IOSProjectMetadata:
        scan_metadata = loaded_outputs.get("scan_metadata") or {}
        project_path = Path(str(scan_metadata.get("project_path", "")))
        project_name = project_path.name
        project_stem = project_path.stem

        ipsw_identity = cls._ipsw_identity(loaded_outputs)
        lief_identity = cls._lief_identity(loaded_outputs)
        strings_identity = cls._strings_identity(loaded_outputs)

        return cls(
            app_display_name=first_non_empty(
                ipsw_identity.get("display_name"),
                ipsw_identity.get("bundle_name"),
                lief_identity.get("display_name"),
                strings_identity.get("display_name"),
                project_stem,
                project_name,
            ),
            file_name=first_non_empty(
                project_name,
                lief_identity.get("file_name"),
                ipsw_identity.get("file_name"),
            ),
            package_name=first_non_empty(
                ipsw_identity.get("bundle_id"),
            ),
            version_code=first_non_empty(
                ipsw_identity.get("version_code"),
            ),
            version_name=first_non_empty(
                ipsw_identity.get("version_name"),
            ),
            main_executable_name=first_non_empty(
                ipsw_identity.get("executable_name"),
                lief_identity.get("executable_name"),
                strings_identity.get("executable_name"),
            ),
            main_binary_path=first_non_empty(
                lief_identity.get("binary_path"),
                ipsw_identity.get("binary_path"),
            ),
            architectures=lief_identity.get("architectures") or [],
            macho_file_type=first_non_empty(lief_identity.get("macho_file_type")),
            imported_function_count=first_non_empty(lief_identity.get("imported_function_count")),
            linked_libraries=lief_identity.get("linked_libraries") or [],
            minimum_os_version=first_non_empty(ipsw_identity.get("minimum_os_version")),
            code_signature_present=first_non_empty(ipsw_identity.get("code_signature_present")),
            has_rpath=first_non_empty(
                ipsw_identity.get("has_rpath"),
                lief_identity.get("has_rpath"),
            ),
        )

    @staticmethod
    def _ipsw_identity(loaded_outputs: dict[str, Any]) -> dict[str, Any]:
        ipsw_outputs = loaded_outputs.get("ipsw_outputs") or {}
        for document in ipsw_outputs.values():
            if not isinstance(document, dict):
                continue
            app_info = document.get("app_info") or {}
            binary = document.get("binary") or {}
            analysis = document.get("analysis") or {}
            macho = analysis.get("macho") if isinstance(analysis, dict) else {}
            code_signature = analysis.get("code_signature") if isinstance(analysis, dict) else {}
            if not isinstance(app_info, dict):
                app_info = {}
            if not isinstance(binary, dict):
                binary = {}
            if not isinstance(macho, dict):
                macho = {}
            if not isinstance(code_signature, dict):
                code_signature = {}

            bundle_id = first_non_empty(app_info.get("bundle_id"))
            if not bundle_id and str(binary.get("kind", "")).strip().lower() != "main":
                continue

            return {
                "bundle_id": bundle_id,
                "bundle_name": first_non_empty(app_info.get("bundle_name")),
                "display_name": first_non_empty(app_info.get("bundle_name")),
                "version_name": first_non_empty(app_info.get("short_version")),
                "version_code": first_non_empty(app_info.get("bundle_version")),
                "executable_name": first_non_empty(app_info.get("executable_name"), binary.get("name")),
                "binary_path": first_non_empty(binary.get("path")),
                "file_name": first_non_empty(binary.get("name")),
                "minimum_os_version": first_non_empty(app_info.get("minimum_os")),
                "code_signature_present": IOSProjectMetadata._stringify_bool(code_signature.get("present")),
                "has_rpath": IOSProjectMetadata._stringify_bool(
                    bool(macho.get("rpaths")) if isinstance(macho.get("rpaths"), list) else None
                ),
            }
        return {}

    @staticmethod
    def _lief_identity(loaded_outputs: dict[str, Any]) -> dict[str, Any]:
        for document in IOSProjectMetadata._primary_lief_documents(loaded_outputs):
            binary = document.get("binary") or {}
            if not isinstance(binary, dict):
                continue
            slices = binary.get("slices")
            if not isinstance(slices, list):
                slices = []

            architectures = [
                str(slice_document.get("architecture", "")).strip()
                for slice_document in slices
                if isinstance(slice_document, dict) and str(slice_document.get("architecture", "")).strip()
            ]
            linked_libraries = sorted(
                {
                    str(library).strip()
                    for slice_document in slices
                    if isinstance(slice_document, dict)
                    for library in (slice_document.get("libraries") or [])
                    if str(library).strip()
                }
            )
            imported_function_count = sum(
                len(slice_document.get("imported_functions") or [])
                for slice_document in slices
                if isinstance(slice_document, dict)
            )
            file_type = first_non_empty(
                *[
                    str(slice_document.get("file_type", "")).strip()
                    for slice_document in slices
                    if isinstance(slice_document, dict)
                ]
            )
            has_rpath = any(
                slice_document.get("has_rpath") is True for slice_document in slices if isinstance(slice_document, dict)
            )

            return {
                "display_name": first_non_empty(binary.get("name")),
                "executable_name": first_non_empty(binary.get("name")),
                "binary_path": first_non_empty(binary.get("path")),
                "file_name": first_non_empty(binary.get("name")),
                "architectures": architectures,
                "macho_file_type": file_type,
                "imported_function_count": str(imported_function_count) if imported_function_count else "",
                "linked_libraries": linked_libraries,
                "has_rpath": IOSProjectMetadata._stringify_bool(has_rpath),
            }
        return {}

    @staticmethod
    def _strings_identity(loaded_outputs: dict[str, Any]) -> dict[str, str]:
        strings_outputs = loaded_outputs.get("strings_outputs") or {}
        if not isinstance(strings_outputs, dict):
            return {}

        for relative_path in strings_outputs:
            path_text = str(relative_path)
            if "/Frameworks/" in path_text or ".framework/" in path_text:
                continue
            path = Path(path_text)
            executable_name = path.stem
            if not executable_name:
                continue
            return {
                "display_name": executable_name,
                "executable_name": executable_name,
            }
        return {}

    @staticmethod
    def _primary_lief_documents(loaded_outputs: dict[str, Any]) -> list[dict[str, Any]]:
        lief_outputs = loaded_outputs.get("lief_outputs") or {}
        if not isinstance(lief_outputs, dict):
            return []
        typed_documents = [document for document in lief_outputs.values() if isinstance(document, dict)]
        if not typed_documents:
            return []
        primary = [
            document
            for document in typed_documents
            if str(((document.get("binary") or {}).get("kind", ""))).strip().lower() == "main"
        ]
        return primary or typed_documents

    @staticmethod
    def _stringify_bool(value: object) -> str:
        if isinstance(value, bool):
            return "true" if value else "false"
        return ""


@dataclass
class IOSMeta:
    app_display_name: str
    file_name: str
    package_name: str
    platform: str
    reviewer_org: str
    scan_date: str
    version_code: str
    version_name: str

    DEFAULT_REVIEWER_ORG = "Phoenix Security Report"

    def __init__(self, loaded_outputs: dict[str, Any]) -> None:
        scan_metadata = loaded_outputs.get("scan_metadata") or {}
        metadata = IOSProjectMetadata.from_loaded_outputs(loaded_outputs)

        self.app_display_name = first_non_empty(
            metadata.app_display_name,
        )
        self.file_name = first_non_empty(metadata.file_name)
        self.package_name = first_non_empty(metadata.package_name)
        self.platform = "iOS"
        self.reviewer_org = self.DEFAULT_REVIEWER_ORG
        self.scan_date = self._derive_scan_date(
            scan_metadata,
            Path(str(loaded_outputs.get("scan_output_path", ""))),
        )
        self.version_code = first_non_empty(metadata.version_code)
        self.version_name = first_non_empty(metadata.version_name)

    @staticmethod
    def _derive_scan_date(scan_metadata: dict[str, Any], scan_output_path: Path) -> str:
        explicit = str(scan_metadata.get("scan_date", "")).strip()
        if explicit:
            return explicit

        try:
            timestamp = scan_output_path.name.rsplit("_", 2)[-2:]
            parsed = datetime.strptime("_".join(timestamp), "%Y-%m-%d_%H-%M-%S")
            return parsed.strftime("%Y-%m-%d %H:%M:%S")
        except (ValueError, IndexError):
            return ""
