"""iOS binary scan-output loader for post-scan processing."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from adapters.post_scan.artifact_loader import ArtifactLoader


class IOSBinaryScanOutputLoader(ArtifactLoader):
    """Load iOS binary scan outputs needed by post-scan processing."""

    def load(self, scan_output_path: Path) -> dict[str, Any]:
        root = Path(scan_output_path)
        return {
            "scan_output_path": str(root),
            "scan_metadata": self._load_json(root / "scan_metadata.json"),
            "opengrep": self._load_json(root / "opengrep_source" / "opengrep_results.json"),
            "ipsw_outputs": self._load_json_documents(root / "ipsw"),
            "lief_outputs": self._load_json_documents(root / "lief"),
            "plist_outputs": self._load_json_documents(root / "plist_binary", exclude={"scan_index.json"}),
            "plist_index": self._load_json(root / "plist_binary" / "scan_index.json"),
            "trufflehog_outputs": self._load_known_json(root / "trufflehog" / "trufflehog_results.json"),
            "gitleaks_outputs": self._load_known_json(root / "gitleaks" / "gitleaks_report.json"),
            "syft_outputs": self._load_known_json(root / "syft" / "sbom.json"),
        }
