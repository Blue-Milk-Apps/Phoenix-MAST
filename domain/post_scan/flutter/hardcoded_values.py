"""Build redacted Flutter source secret evidence."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from domain.post_scan.flutter.scan_extraction_context import FlutterScanExtractionContext


@dataclass
class FlutterHardcodedValues:
    urls: list[dict[str, str]]
    emails: list[str]
    secrets: list[dict[str, str]]
    gitleaks_assessed: bool
    trufflehog_assessed: bool
    assessed: bool

    def __init__(self, context: FlutterScanExtractionContext) -> None:
        self.urls = []
        self.emails = []
        self.gitleaks_assessed = context.gitleaks_assessed
        self.trufflehog_assessed = context.trufflehog_assessed
        self.assessed = self.gitleaks_assessed or self.trufflehog_assessed
        secrets = [
            *(self._gitleaks_secret(context, finding) for finding in context.gitleaks_findings),
            *(self._trufflehog_secret(context, finding) for finding in context.trufflehog_findings),
        ]
        self.secrets = self._deduplicate(secrets)

    @classmethod
    def _gitleaks_secret(
        cls,
        context: FlutterScanExtractionContext,
        finding: dict[str, Any],
    ) -> dict[str, str]:
        label = context.first_non_empty(
            finding.get("Description"),
            finding.get("description"),
            finding.get("RuleID"),
            finding.get("rule_id"),
            "Gitleaks finding",
        )
        return {
            "value": cls._redacted_value(label),
            "location": cls._location(
                context,
                finding.get("File", finding.get("file")),
                finding.get("StartLine", finding.get("start_line")),
            ),
        }

    @classmethod
    def _trufflehog_secret(
        cls,
        context: FlutterScanExtractionContext,
        finding: dict[str, Any],
    ) -> dict[str, str]:
        label = context.first_non_empty(
            finding.get("DetectorName"),
            finding.get("DetectorDescription"),
            finding.get("detector_name"),
            "TruffleHog finding",
        )
        source_metadata = finding.get("SourceMetadata")
        source_data = source_metadata.get("Data") if isinstance(source_metadata, dict) else {}
        filesystem = source_data.get("Filesystem") if isinstance(source_data, dict) else {}
        filesystem = filesystem if isinstance(filesystem, dict) else {}
        return {
            "value": cls._redacted_value(label),
            "location": cls._location(
                context,
                filesystem.get("file"),
                filesystem.get("line"),
            ),
        }

    @staticmethod
    def _redacted_value(label: str) -> str:
        return f"{label} credential (redacted)"

    @staticmethod
    def _location(
        context: FlutterScanExtractionContext,
        raw_path: object,
        line: object,
    ) -> str:
        text = str(raw_path or "").strip()
        if text:
            path = Path(text)
            if path.is_absolute():
                try:
                    text = path.relative_to(context.project_path).as_posix()
                except ValueError:
                    text = path.as_posix()
        return f"{text}:{line}" if text and line not in (None, "") else text

    @staticmethod
    def _deduplicate(secrets: list[dict[str, str]]) -> list[dict[str, str]]:
        seen: set[tuple[str, str]] = set()
        deduplicated: list[dict[str, str]] = []
        for secret in secrets:
            key = (secret["value"].casefold(), secret["location"])
            if key in seen:
                continue
            seen.add(key)
            deduplicated.append(secret)
        return deduplicated
