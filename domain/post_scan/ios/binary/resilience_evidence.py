"""Build default iOS resilience evidence section."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from domain.post_scan.ios.common.evidence import EvidenceEntry


@dataclass
class IOSResilienceEvidence:
    biometric_bypass_possible: EvidenceEntry
    debug_symbols_present: EvidenceEntry

    def __init__(self, loaded_outputs: dict[str, Any]) -> None:
        _ = loaded_outputs
        self.biometric_bypass_possible = EvidenceEntry(
            None,
            "source_control_flow_and_runtime_authentication_testing_required",
        )
        self.debug_symbols_present = EvidenceEntry(False, "no_debug_symbols_present_hits")
