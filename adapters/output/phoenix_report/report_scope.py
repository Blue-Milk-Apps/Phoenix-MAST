"""Resolve presentation and assessment scope for Phoenix reports."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class ReportScope:
    """Describe which report content applies to the current scan target."""

    platform: str
    target_type: str
    assessment_label: str
    assessment_title: str
    target_label: str
    target_information_heading: str
    show_file_hashes: bool
    show_ios_binary_analysis: bool
    assessed_sections: tuple[str, ...]


def resolve_report_scope(data: dict[str, Any]) -> ReportScope:
    """Build report behavior from explicit metadata with legacy-safe fallbacks."""

    meta = data.get("meta") if isinstance(data.get("meta"), dict) else {}
    platform = str(meta.get("platform") or "").strip()
    target_type = _target_type(data, meta)
    is_source = target_type == "SOURCE"
    is_ios = platform.lower() == "ios"

    if is_ios and is_source:
        assessed_sections = ("code", "network", "data storage")
    else:
        assessed_sections = ("code", "network", "data storage", "resilience")

    return ReportScope(
        platform=platform,
        target_type=target_type,
        assessment_label="Source Code" if is_source else "Binary",
        assessment_title=(
            "Source Code Vulnerability Assessment" if is_source else "Application Vulnerability Assessment"
        ),
        target_label="Project Name" if is_source else "File Name",
        target_information_heading="Source Project Information" if is_source else "File Information",
        show_file_hashes=not is_source,
        show_ios_binary_analysis=is_ios and not is_source,
        assessed_sections=assessed_sections,
    )


def _target_type(data: dict[str, Any], meta: dict[str, Any]) -> str:
    explicit = str(meta.get("target_type") or "").strip().upper()
    if explicit in {"SOURCE", "BINARY"}:
        return explicit

    file_name = str(meta.get("file_name") or "").strip()
    has_ipa_evidence = bool(data.get("ipa_binary_evidence") or data.get("ipa_binary_protections"))
    if has_ipa_evidence or Path(file_name).suffix.lower() == ".ipa":
        return "BINARY"

    # Existing reports predate target_type and were generated from binaries.
    return "BINARY"
