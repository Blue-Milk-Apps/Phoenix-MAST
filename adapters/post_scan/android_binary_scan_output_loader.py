"""Android binary scan-output loader for post-scan processing."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from adapters.post_scan.artifact_loader import ArtifactLoader


class AndroidBinaryScanOutputLoader(ArtifactLoader):
    """Load Android binary scan outputs needed by post-scan processing."""

    def load(self, scan_output_path: Path) -> dict[str, Any]:
        root = Path(scan_output_path)
        return {
            "scan_output_path": str(root),
            "gitleaks_outputs": self._load_known_json(root / "gitleaks" / "gitleaks_report.json"),
            "trufflehog_outputs": self._load_known_json(root / "trufflehog" / "trufflehog_results.json"),
            "syft_outputs": self._load_known_json(root / "syft" / "sbom.json"),
            "scan_metadata": self._load_json(root / "scan_metadata.json"),
            "opengrep": self._load_binary_opengrep(root),
            "androguard_components": self._load_json(root / "androguard" / "components.json"),
            "androguard_metadata": self._load_json(root / "androguard" / "metadata.json"),
            "androguard_permissions": self._load_json(root / "androguard" / "permissions.json"),
            "androguard_certificates": self._load_json(root / "androguard" / "certificates.json"),
            "aapt2_components": self._load_json(root / "aapt2" / "components.json"),
            "aapt2_identity": self._load_json(root / "aapt2" / "identity.json"),
            "aapt2_application": self._load_json(root / "aapt2" / "application.json"),
            "aapt2_manifest_security_posture": self._load_json(root / "aapt2" / "manifest_security_posture.json"),
            "aapt2_permissions": self._load_json(root / "aapt2" / "permissions.json"),
            "apksigner_signing_evidence": self._load_json(root / "apksigner" / "signing_evidence.json"),
            "apktool_manifest_summary": self._load_json(root / "apktool" / "manifest_summary.json"),
            "apktool_permissions": self._load_json(root / "apktool" / "permissions.json"),
            "apktool_network_security_config": self._load_json(root / "apktool" / "network_security_config.json"),
            "apktool_deep_links": self._load_json(root / "apktool" / "deep_links.json"),
        }
