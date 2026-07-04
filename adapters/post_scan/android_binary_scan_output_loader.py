"""Android binary scan-output loader for post-scan processing."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from ports.scan_output_loader_port import ScanOutputLoaderPort


class AndroidBinaryScanOutputLoader(ScanOutputLoaderPort):
    """Load Android binary scan outputs needed by post-scan processing."""

    def load(self, scan_output_path: Path) -> dict[str, Any]:
        root = Path(scan_output_path)
        return {
            "scan_output_path": str(root),
            "scan_metadata": self._load_json(root / "scan_metadata.json"),
            "opengrep": self._load_json(root / "opengrep_source" / "opengrep_results.json"),
            "androguard_metadata": self._load_json(root / "androguard" / "metadata.json"),
            "androguard_certificates": self._load_json(root / "androguard" / "certificates.json"),
            "aapt2_identity": self._load_json(root / "aapt2" / "identity.json"),
            "aapt2_application": self._load_json(root / "aapt2" / "application.json"),
            "apksigner_signing_evidence": self._load_json(root / "apksigner" / "signing_evidence.json"),
        }

    @staticmethod
    def _load_json(path: Path) -> dict[str, Any] | None:
        if not path.is_file():
            return None

        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            return None
