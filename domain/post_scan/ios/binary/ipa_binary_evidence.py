"""Structural facts reported by iOS tools; unavailable facts remain unknown."""

from dataclasses import dataclass
from typing import Any


@dataclass
class IOSIPABinaryEvidence:
    nx: bool | None = None
    pie: bool | None = None
    stack_canary: bool | None = None
    arc: bool | None = None
    rpath: bool | None = None
    code_signature: bool | None = None
    encrypted: bool | None = None
    symbols_stripped: bool | None = None

    def __init__(self, loaded_outputs: dict[str, Any]) -> None:
        slices = [
            item
            for document in self._primary_documents(loaded_outputs.get("lief_outputs"))
            for item in document["binary"].get("slices", [])
            if isinstance(item, dict)
        ]
        ipsw = self._primary_documents(loaded_outputs.get("ipsw_outputs"))
        self.nx = self._consensus([item.get("has_nx") for item in slices])
        self.pie = self._consensus(
            [
                bool({str(flag).upper() for flag in item["flags"]} & {"PIE", "MH_PIE"})
                if isinstance(item.get("flags"), list)
                else None
                for item in slices
            ]
        )
        self.rpath = self._consensus(
            [
                bool(paths)
                if isinstance(paths := (document.get("analysis", {}).get("macho") or {}).get("rpaths"), list)
                else None
                for document in ipsw
            ]
        )
        self.code_signature = self._consensus(
            [(document.get("analysis", {}).get("code_signature") or {}).get("present") for document in ipsw]
        )
        # Symbol-name guesses are OpenGrep's responsibility, not structural metadata.
        self.stack_canary = self.arc = self.encrypted = self.symbols_stripped = None

    @staticmethod
    def _primary_documents(documents: Any) -> list[dict[str, Any]]:
        if not isinstance(documents, dict):
            return []
        return [
            document
            for document in documents.values()
            if isinstance(document, dict)
            and isinstance(document.get("binary"), dict)
            and document["binary"].get("kind") == "main"
            and not document["binary"].get("error")
        ]

    @staticmethod
    def _consensus(values: list[object]) -> bool | None:
        if not values or any(not isinstance(value, bool) for value in values):
            return None
        return values[0] if all(value == values[0] for value in values) else None
