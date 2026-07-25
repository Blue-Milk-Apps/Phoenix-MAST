"""Helpers for resolving filesystem scan targets for scanners."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from domain.models import ScanConfig
from utilities.ipa_utils import ExtractedIPA, extract_ipa, is_ipa_file


@dataclass
class ResolvedScanTarget:
    """Filesystem path a scanner should inspect, plus optional extraction state."""

    path: Path
    extracted_ipa: ExtractedIPA | None = None

    def cleanup(self) -> None:
        """Remove any temporary extraction artifacts created during resolution."""
        if self.extracted_ipa is not None:
            self.extracted_ipa.cleanup()


def resolve_scan_target(config: ScanConfig) -> ResolvedScanTarget:
    """Return the best available filesystem path for scanners to inspect."""
    project_path = config.project_path

    if project_path.is_dir():
        return ResolvedScanTarget(path=project_path)

    if project_path.is_file() and is_ipa_file(project_path):
        extracted = extract_ipa(project_path)
        return ResolvedScanTarget(path=extracted.app_bundle, extracted_ipa=extracted)

    return ResolvedScanTarget(path=project_path)
