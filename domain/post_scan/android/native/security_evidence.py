"""Shared native Android source security-evidence helpers."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from domain.post_scan.android.native.scan_extraction_context import NativeAndroidScanExtractionContext


@dataclass
class NativeAndroidEvidenceEntry:
    present: bool | None
    evidence: str = ""
    details: list[str] = field(default_factory=list)


def opengrep_entry(
    context: NativeAndroidScanExtractionContext,
    rule_ids: frozenset[str],
    absent_evidence: str,
) -> NativeAndroidEvidenceEntry:
    matches: list[str] = []
    for result in context.opengrep_results:
        if str(result.get("check_id", "")).strip() not in rule_ids:
            continue
        evidence = _opengrep_evidence(context, result)
        if evidence and evidence not in matches:
            matches.append(evidence)
    if matches:
        return NativeAndroidEvidenceEntry(True, "; ".join(matches[:5]), matches[:10])
    if context.opengrep_security_assessed:
        return NativeAndroidEvidenceEntry(False, absent_evidence, [])
    return NativeAndroidEvidenceEntry(None)


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


def _opengrep_evidence(
    context: NativeAndroidScanExtractionContext,
    result: dict[str, Any],
) -> str:
    extra = result.get("extra") if isinstance(result.get("extra"), dict) else {}
    path = _relative_path(context, str(result.get("path", "")).strip())
    start = result.get("start") if isinstance(result.get("start"), dict) else {}
    line = start.get("line")
    location = f"{path}:{line}" if path and line not in (None, "") else path
    message = str(extra.get("message", "")).strip()
    if location and message:
        return f"{location}: {message}"
    return location or message or str(result.get("check_id", "")).strip()


def _relative_path(context: NativeAndroidScanExtractionContext, value: str) -> str:
    if not value:
        return ""
    path = Path(value)
    if not path.is_absolute():
        return path.as_posix()
    try:
        return path.relative_to(context.project_path).as_posix()
    except ValueError:
        return path.as_posix()
