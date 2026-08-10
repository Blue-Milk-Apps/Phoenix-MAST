"""Android binary scan-output loader for post-scan processing."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from ports.post_scan.scan_output_loader_port import ScanOutputLoaderPort


class AndroidBinaryScanOutputLoader(ScanOutputLoaderPort):
    """Load Android binary scan outputs needed by post-scan processing."""

    def load(self, scan_output_path: Path) -> dict[str, Any]:
        root = Path(scan_output_path)
        return {
            "scan_output_path": str(root),
            "scan_metadata": self._load_json(root / "scan_metadata.json"),
            "opengrep": self._load_json(root / "opengrep_source" / "opengrep_results.json"),
            "androguard_components": self._load_json(root / "androguard" / "components.json"),
            "androguard_findings": self._load_json(root / "androguard" / "findings.json"),
            "androguard_metadata": self._load_json(root / "androguard" / "metadata.json"),
            "androguard_permissions": self._load_json(root / "androguard" / "permissions.json"),
            "androguard_api_calls": self._load_json(root / "androguard" / "api_calls.json"),
            "androguard_certificates": self._load_json(root / "androguard" / "certificates.json"),
            "androguard_report_summary": self._load_json(root / "androguard" / "report_summary.json"),
            "androguard_strings": self._load_json(root / "androguard" / "strings.json"),
            "aapt2_components": self._load_json(root / "aapt2" / "components.json"),
            "aapt2_identity": self._load_json(root / "aapt2" / "identity.json"),
            "aapt2_application": self._load_json(root / "aapt2" / "application.json"),
            "aapt2_manifest_security_posture": self._load_json(root / "aapt2" / "manifest_security_posture.json"),
            "aapt2_permissions": self._load_json(root / "aapt2" / "permissions.json"),
            "apksigner_signing_evidence": self._load_json(root / "apksigner" / "signing_evidence.json"),
            "apktool_code_indicators": self._load_json(root / "apktool" / "code_indicators.json"),
            "apktool_manifest_summary": self._load_json(root / "apktool" / "manifest_summary.json"),
            "apktool_permissions": self._load_json(root / "apktool" / "permissions.json"),
            "apktool_secrets_endpoints": self._load_json(root / "apktool" / "secrets_endpoints.json"),
            "apktool_network_security_config": self._load_json(root / "apktool" / "network_security_config.json"),
            "apktool_deep_links": self._load_json(root / "apktool" / "deep_links.json"),
            "strings_outputs": self._load_strings_outputs(root / "strings"),
        }

    @staticmethod
    def _load_json(path: Path) -> dict[str, Any] | None:
        if not path.is_file():
            return None

        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            return None

    @staticmethod
    def _load_strings_outputs(strings_root: Path) -> dict[str, str]:
        if not strings_root.is_dir():
            return {}

        outputs: dict[str, str] = {}
        for path in sorted(strings_root.glob("*.txt")):
            outputs[path.name] = path.read_text(encoding="utf-8", errors="ignore")
        return outputs
