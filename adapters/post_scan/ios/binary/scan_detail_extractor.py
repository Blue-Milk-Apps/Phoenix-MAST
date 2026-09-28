"""iOS binary detail extractor for post-scan processing."""

from __future__ import annotations

from dataclasses import asdict
from typing import Any

from domain.post_scan.dependencies import syft_packages
from domain.post_scan.ios.binary.app_info import IOSAppInfo
from domain.post_scan.ios.binary.endpoints import IOSEndpoints
from domain.post_scan.ios.binary.file_info import IOSFileInfo
from domain.post_scan.ios.binary.ipa_binary_evidence import IOSIPABinaryEvidence
from domain.post_scan.ios.binary.meta import IOSMeta
from domain.post_scan.ios.binary.url_schemes import IOSURLSchemes
from domain.post_scan.ios.common.permissions import IOSPermissions
from domain.post_scan.rule_assessment import RuleFunctionality, assessments_from_outputs
from domain.post_scan.utilities import secret_values
from ports.post_scan.scan_detail_extractor_port import ScanDetailExtractorPort


class IOSBinaryScanDetailExtractor(ScanDetailExtractorPort):
    """Extract iOS-binary-specific sections from loaded scan outputs."""

    def extract_sections(self, loaded_outputs: dict[str, Any]) -> dict[str, Any]:
        ipa_binary_evidence = IOSIPABinaryEvidence(loaded_outputs)

        return {
            "meta": asdict(IOSMeta(loaded_outputs)),
            "file_info": asdict(IOSFileInfo(loaded_outputs)),
            "app_info": asdict(IOSAppInfo(loaded_outputs)),
            "ipa_binary_evidence": {
                "nx": ipa_binary_evidence.nx,
                "pie": ipa_binary_evidence.pie,
                "stack canary": ipa_binary_evidence.stack_canary,
                "arc": ipa_binary_evidence.arc,
                "rpath": ipa_binary_evidence.rpath,
                "code signature": ipa_binary_evidence.code_signature,
                "encrypted": ipa_binary_evidence.encrypted,
                "symbols stripped": ipa_binary_evidence.symbols_stripped,
            },
            "url_schemes": IOSURLSchemes(loaded_outputs).items,
            "functionality": RuleFunctionality(
                loaded_outputs.get("opengrep"), assessments=assessments_from_outputs(loaded_outputs)
            ).items,
            "third_party_sdks": {"Packages": {p["name"]: True for p in syft_packages(loaded_outputs)}},
            "permissions": IOSPermissions(loaded_outputs).items,
            "hardcoded_values": secret_values(loaded_outputs),
            "endpoints": IOSEndpoints(loaded_outputs).items,
        }
