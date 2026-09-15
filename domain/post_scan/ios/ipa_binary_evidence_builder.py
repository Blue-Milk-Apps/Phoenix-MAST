"""Build iOS IPA binary evidence section from binary scanner outputs."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass
class IOSIPABinaryEvidence:
    STACK_CANARY_IMPORTS = frozenset({"___stack_chk_fail", "___stack_chk_guard"})
    ARC_IMPORTS = frozenset({"_objc_release", "_swift_release"})

    nx: bool = False
    pie: bool = False
    stack_canary: bool = False
    arc: bool = False
    rpath: bool = False
    code_signature: bool = False
    encrypted: bool = False
    symbols_stripped: bool = False

    def __init__(self, loaded_outputs: dict[str, Any]) -> None:
        ipsw_documents = self._primary_documents(loaded_outputs.get("ipsw_outputs"))
        lief_documents = self._primary_documents(loaded_outputs.get("lief_outputs"))

        self.nx = self._nx_enabled(lief_documents)
        self.pie = self._pie_enabled(ipsw_documents, lief_documents)
        self.stack_canary = self._stack_canary_enabled(lief_documents)
        self.arc = self._arc_enabled(lief_documents)
        self.rpath = self._has_rpath(ipsw_documents)
        self.code_signature = self._has_code_signature(ipsw_documents)
        self.encrypted = False
        self.symbols_stripped = False

    @classmethod
    def _primary_documents(
        cls,
        documents: Any,
    ) -> list[dict[str, Any]]:
        if not isinstance(documents, dict):
            return []

        typed_documents = [document for document in documents.values() if isinstance(document, dict)]
        if not typed_documents:
            return []

        primary = [document for document in typed_documents if cls._binary_kind(document) == "main"]
        return primary or typed_documents

    @staticmethod
    def _binary_kind(document: dict[str, Any]) -> str:
        binary = document.get("binary")
        if not isinstance(binary, dict):
            return ""
        return str(binary.get("kind", "")).strip().lower()

    @classmethod
    def _pie_enabled(
        cls,
        ipsw_documents: list[dict[str, Any]],
        lief_documents: list[dict[str, Any]],
    ) -> bool:
        if cls._lief_flag_present(lief_documents, "PIE", "MH_PIE"):
            return True

        for document in ipsw_documents:
            header_flags = cls._ipsw_header_flags(document)
            if any(flag in {"PIE", "MH_PIE"} for flag in header_flags):
                return True
        return False

    @classmethod
    def _nx_enabled(cls, lief_documents: list[dict[str, Any]]) -> bool:
        explicit = cls._lief_slice_boolean(lief_documents, "has_nx")
        if explicit is not None:
            return explicit

        nx_heap = cls._lief_slice_boolean(lief_documents, "has_nx_heap")
        nx_stack = cls._lief_slice_boolean(lief_documents, "has_nx_stack")
        if nx_heap is True or nx_stack is True:
            return True

        return cls._lief_flag_present(
            lief_documents,
            "NO_HEAP_EXECUTION",
            "NX_HEAP",
        )

    @classmethod
    def _stack_canary_enabled(cls, lief_documents: list[dict[str, Any]]) -> bool:
        for imported_functions in cls._lief_imported_function_sets(lief_documents):
            if cls.STACK_CANARY_IMPORTS.issubset(imported_functions):
                return True
        return False

    @classmethod
    def _arc_enabled(cls, lief_documents: list[dict[str, Any]]) -> bool:
        for imported_functions in cls._lief_imported_function_sets(lief_documents):
            if imported_functions & cls.ARC_IMPORTS:
                return True
        return False

    @staticmethod
    def _has_rpath(ipsw_documents: list[dict[str, Any]]) -> bool:
        for document in ipsw_documents:
            analysis = document.get("analysis")
            if not isinstance(analysis, dict):
                continue
            macho = analysis.get("macho")
            if not isinstance(macho, dict):
                continue
            rpaths = macho.get("rpaths")
            if isinstance(rpaths, list) and any(str(item).strip() for item in rpaths):
                return True
        return False

    @staticmethod
    def _has_code_signature(ipsw_documents: list[dict[str, Any]]) -> bool:
        for document in ipsw_documents:
            analysis = document.get("analysis")
            if not isinstance(analysis, dict):
                continue
            code_signature = analysis.get("code_signature")
            if not isinstance(code_signature, dict):
                continue
            if code_signature.get("present") is True:
                return True
        return False

    @staticmethod
    def _ipsw_header_flags(document: dict[str, Any]) -> set[str]:
        analysis = document.get("analysis")
        if not isinstance(analysis, dict):
            return set()
        macho = analysis.get("macho")
        if not isinstance(macho, dict):
            return set()
        header = macho.get("header")
        if not isinstance(header, dict):
            return set()

        raw_flags = header.get("flags")
        if isinstance(raw_flags, list):
            values = raw_flags
        elif raw_flags is None:
            values = []
        else:
            values = [raw_flags]
        return {str(value).strip().upper() for value in values if str(value).strip()}

    @staticmethod
    def _lief_flag_present(documents: list[dict[str, Any]], *expected_flags: str) -> bool:
        normalized_expected = {flag.strip().upper() for flag in expected_flags if flag.strip()}
        if not normalized_expected:
            return False

        for document in documents:
            binary = document.get("binary")
            if not isinstance(binary, dict):
                continue
            slices = binary.get("slices")
            if not isinstance(slices, list):
                continue
            for slice_document in slices:
                if not isinstance(slice_document, dict):
                    continue
                flags = slice_document.get("flags")
                if not isinstance(flags, list):
                    continue
                normalized_flags = {str(flag).strip().upper() for flag in flags if str(flag).strip()}
                if normalized_flags & normalized_expected:
                    return True
        return False

    @staticmethod
    def _lief_slice_boolean(documents: list[dict[str, Any]], key: str) -> bool | None:
        for document in documents:
            binary = document.get("binary")
            if not isinstance(binary, dict):
                continue
            slices = binary.get("slices")
            if not isinstance(slices, list):
                continue
            for slice_document in slices:
                if not isinstance(slice_document, dict):
                    continue
                value = slice_document.get(key)
                if isinstance(value, bool):
                    return value
        return None

    @staticmethod
    def _lief_imported_function_sets(documents: list[dict[str, Any]]) -> list[set[str]]:
        imported_function_sets: list[set[str]] = []
        for document in documents:
            binary = document.get("binary")
            if not isinstance(binary, dict):
                continue
            slices = binary.get("slices")
            if not isinstance(slices, list):
                continue
            for slice_document in slices:
                if not isinstance(slice_document, dict):
                    continue
                imported_functions = slice_document.get("imported_functions")
                if not isinstance(imported_functions, list):
                    continue
                imported_function_sets.append({str(item).strip() for item in imported_functions if str(item).strip()})
        return imported_function_sets
