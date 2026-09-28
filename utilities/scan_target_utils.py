"""Helpers for resolving filesystem scan targets for scanners."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from domain.models import ExtractedBinary, ScanConfig
from utilities.ipa_utils import extract_ipa, is_ipa_file


@dataclass
class ResolvedScanTarget:
    """Filesystem path a scanner should inspect, plus optional extraction state."""

    path: Path
    owned_extraction: ExtractedBinary | None = None

    def cleanup(self) -> None:
        """Remove any temporary extraction artifacts created during resolution."""
        if self.owned_extraction is not None:
            self.owned_extraction.cleanup()


def resolve_scan_target(config: ScanConfig) -> ResolvedScanTarget:
    """Return the best available filesystem path for scanners to inspect."""
    project_path = config.project_path

    decoded = config.output_path / "apktool" / "decoded"
    if config.target_type == "BINARY" and config.platform == "ANDROID" and decoded.is_dir():
        return ResolvedScanTarget(path=decoded)
    if config.extracted_binary is not None:
        return ResolvedScanTarget(path=config.extracted_binary.scan_root_path)

    if project_path.is_dir():
        return ResolvedScanTarget(path=project_path)

    if project_path.is_file() and is_ipa_file(project_path):
        extracted = extract_ipa(project_path)
        return ResolvedScanTarget(path=extracted.app_bundle, owned_extraction=extracted)

    return ResolvedScanTarget(path=project_path)


def secret_scan_paths(config: ScanConfig, target: ResolvedScanTarget) -> tuple[Path, ...]:
    """Include extracted text without rescanning reports or other tool artifacts."""
    strings = config.output_path / "strings"
    if (
        config.target_type == "BINARY"
        and strings.is_dir()
        and not strings.resolve().is_relative_to(target.path.resolve())
    ):
        return target.path, strings
    return (target.path,)
