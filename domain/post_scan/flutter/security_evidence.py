"""Shared Flutter source security-evidence helpers."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable

from domain.post_scan.flutter.scan_extraction_context import FlutterScanExtractionContext


@dataclass(frozen=True)
class FlutterEvidenceEntry:
    present: bool | None
    evidence: str = ""
    details: list[str] = field(default_factory=list)


def scoped_opengrep_entry(
    context: FlutterScanExtractionContext,
    *,
    scope: str,
    rule_ids: frozenset[str],
    absent_evidence: str,
) -> FlutterEvidenceEntry:
    """Build evidence without treating an incomplete scoped scan as clean."""

    if not rule_ids:
        return FlutterEvidenceEntry(None)

    matches = [
        _opengrep_evidence(context, result)
        for result in context.opengrep_results_for_scope(scope)
        if context.first_non_empty(result.get("check_id")) in rule_ids
    ]
    matches = _deduplicate(item for item in matches if item)
    if matches:
        return FlutterEvidenceEntry(True, "; ".join(matches[:5]), matches[:10])

    configured_rule_ids = context.opengrep_configured_rule_ids(scope)
    if context.opengrep_scope_assessed(scope) and rule_ids <= configured_rule_ids:
        return FlutterEvidenceEntry(False, absent_evidence, [])
    return FlutterEvidenceEntry(None)


def combine_evidence_entries(
    entries: Iterable[FlutterEvidenceEntry],
    *,
    absent_evidence: str,
) -> FlutterEvidenceEntry:
    """Combine evidence while allowing a positive result to dominate unknowns."""

    values = list(entries)
    detected = [entry for entry in values if entry.present is True]
    if detected:
        evidence = _deduplicate(entry.evidence for entry in detected if entry.evidence)
        details = _deduplicate(detail for entry in detected for detail in entry.details if detail)
        return FlutterEvidenceEntry(True, "; ".join(evidence[:5]), details[:10])
    if values and all(entry.present is False for entry in values):
        return FlutterEvidenceEntry(False, absent_evidence, [])
    return FlutterEvidenceEntry(None)


def optional_bool_entry(
    value: object,
    *,
    label: str,
    invert: bool = False,
) -> FlutterEvidenceEntry:
    if not isinstance(value, bool):
        return FlutterEvidenceEntry(None)
    present = not value if invert else value
    return FlutterEvidenceEntry(present, f"{label}={str(value).lower()}", [])


def opengrep_scope_applicable(context: FlutterScanExtractionContext, scope: str) -> bool:
    """Return whether a scoped scan is relevant or was actually attempted."""

    if scope == "flutter":
        return True
    if scope == "android" and (context.platforms.get("android", False) or context.android_available):
        return True
    if scope == "ios" and (context.platforms.get("ios", False) or context.ios_available):
        return True
    if context.opengrep_results_for_scope(scope):
        return True
    scope_metadata = context.opengrep_scope(scope)
    return bool(scope_metadata) and scope_metadata.get("status") != "skipped"


def _opengrep_evidence(
    context: FlutterScanExtractionContext,
    result: dict[str, Any],
) -> str:
    path = _relative_path(context, context.first_non_empty(result.get("path")))
    start = result.get("start")
    start = start if isinstance(start, dict) else {}
    line = start.get("line")
    location = f"{path}:{line}" if path and line not in (None, "") else path
    extra = result.get("extra")
    extra = extra if isinstance(extra, dict) else {}
    message = context.first_non_empty(extra.get("message"))
    if location and message:
        return f"{location}: {message}"
    return location or message or context.first_non_empty(result.get("check_id"))


def _relative_path(context: FlutterScanExtractionContext, value: str) -> str:
    if not value:
        return ""
    path = Path(value)
    if not path.is_absolute():
        return path.as_posix()
    try:
        return path.relative_to(context.project_path).as_posix()
    except ValueError:
        return path.as_posix()


def _deduplicate(values: Iterable[str]) -> list[str]:
    return list(dict.fromkeys(values))
