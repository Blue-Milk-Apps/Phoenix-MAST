"""Build redacted native Android source secret evidence."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from domain.post_scan.android.native.scan_extraction_context import NativeAndroidScanExtractionContext


@dataclass
class NativeAndroidHardcodedValues:
    urls: list[dict[str, str]]
    emails: list[str]
    secrets: list[dict[str, str]]
    assessed: bool

    def __init__(self, context: NativeAndroidScanExtractionContext) -> None:
        self.urls = []
        self.emails = []
        self.assessed = context.gitleaks_assessed or context.trufflehog_assessed
        secrets = [
            *(self._gitleaks_secret(context, finding) for finding in context.gitleaks_findings),
            *(self._trufflehog_secret(context, finding) for finding in context.trufflehog_findings),
        ]
        self.secrets = self._deduplicate(secrets)

    @classmethod
    def _gitleaks_secret(
        cls,
        context: NativeAndroidScanExtractionContext,
        finding: dict[str, Any],
    ) -> dict[str, str]:
        label = context.first_non_empty(
            finding.get("Description"),
            finding.get("RuleID"),
            "Gitleaks finding",
        )
        return {
            "value": f"{label} (redacted)",
            "location": cls._location(
                context,
                finding.get("File"),
                finding.get("StartLine"),
            ),
        }

    @classmethod
    def _trufflehog_secret(
        cls,
        context: NativeAndroidScanExtractionContext,
        finding: dict[str, Any],
    ) -> dict[str, str]:
        label = context.first_non_empty(
            finding.get("DetectorName"),
            finding.get("DetectorDescription"),
            "TruffleHog finding",
        )
        source_metadata = finding.get("SourceMetadata")
        source_data = source_metadata.get("Data") if isinstance(source_metadata, dict) else {}
        filesystem = source_data.get("Filesystem") if isinstance(source_data, dict) else {}
        filesystem = filesystem if isinstance(filesystem, dict) else {}
        return {
            "value": f"{label} credential (redacted)",
            "location": cls._location(
                context,
                filesystem.get("file"),
                filesystem.get("line"),
            ),
        }

    @staticmethod
    def _location(
        context: NativeAndroidScanExtractionContext,
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
            key = (secret["value"], secret["location"])
            if key in seen:
                continue
            seen.add(key)
            deduplicated.append(secret)
        return deduplicated
