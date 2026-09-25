"""Shared native Android source security-evidence helpers."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class NativeAndroidEvidenceEntry:
    present: bool | None
    evidence: str = ""
    details: list[str] = field(default_factory=list)


def optional_bool_entry(
    value: object,
    *,
    label: str,
    invert: bool = False,
) -> NativeAndroidEvidenceEntry:
    if not isinstance(value, bool):
        return NativeAndroidEvidenceEntry(None)
    present = not value if invert else value
    return NativeAndroidEvidenceEntry(present, f"{label}={str(value).lower()}", [])
