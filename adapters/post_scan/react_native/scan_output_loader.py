"""React Native source scan-output loader for post-scan processing."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from ports.post_scan.scan_output_loader_port import ScanOutputLoaderPort


class ReactNativeScanOutputLoader(ScanOutputLoaderPort):
    """Load persisted React Native and embedded-platform source scan artifacts."""

    SCAN_METADATA_PATH = Path("scan_metadata.json")
    SOURCE_METADATA_PATH = Path("react_native_metadata/project_metadata.json")
    OPENGREP_PATH = Path("opengrep_source/opengrep_results.json")
    PLIST_ROOT = Path("plist_source")
    PLIST_INDEX_PATH = PLIST_ROOT / "scan_index.json"
    TRUFFLEHOG_PATH = Path("trufflehog/trufflehog_results.json")
    GITLEAKS_PATH = Path("gitleaks/gitleaks_report.json")
    SYFT_PATH = Path("syft/sbom.json")

    def load(self, scan_output_path: Path) -> dict[str, Any]:
        root = Path(scan_output_path)
        return {
            "scan_output_path": str(root),
            "scan_metadata": None,
            "source_metadata": None,
            "opengrep": None,
            "plist_outputs": {},
            "plist_index": None,
            "trufflehog_outputs": {},
            "gitleaks_outputs": {},
            "syft_outputs": {},
        }
