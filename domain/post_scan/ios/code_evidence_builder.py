"""Build default iOS code evidence section."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass
class EvidenceEntry:
    present: bool = False
    evidence: str = ""


@dataclass
class IOSCodeEvidence:
    uses_uiwebview: EvidenceEntry
    insecure_nanopb_library: EvidenceEntry
    insecure_nskeyedunarchiver_usage: EvidenceEntry
    missing_arc: EvidenceEntry
    pic_not_enabled: EvidenceEntry
    stack_canaries_not_enabled: EvidenceEntry
    insecure_api_usage_in_binary: EvidenceEntry
    malloc_instead_of_calloc: EvidenceEntry
    encodes_data_using_insecure_cryptography: EvidenceEntry
    utilizes_insecure_cryptography: EvidenceEntry
    pbkdf2_iteration_count_below_10k: EvidenceEntry
    hardcoded_api_keys_in_bundle: EvidenceEntry
    insecure_entitlements: EvidenceEntry

    def __init__(self, loaded_outputs: dict[str, Any]) -> None:
        _ = loaded_outputs
        self.uses_uiwebview = EvidenceEntry(False, "no_uses_uiwebview_hits")
        self.insecure_nanopb_library = EvidenceEntry(False, "no_insecure_nanopb_library_hits")
        self.insecure_nskeyedunarchiver_usage = EvidenceEntry(False, "no_insecure_nskeyedunarchiver_usage_hits")
        self.missing_arc = EvidenceEntry(False, "no_missing_arc_hits")
        self.pic_not_enabled = EvidenceEntry(False, "no_pic_not_enabled_hits")
        self.stack_canaries_not_enabled = EvidenceEntry(False, "no_stack_canaries_not_enabled_hits")
        self.insecure_api_usage_in_binary = EvidenceEntry(False, "no_insecure_api_usage_in_binary_hits")
        self.malloc_instead_of_calloc = EvidenceEntry(False, "no_malloc_instead_of_calloc_hits")
        self.encodes_data_using_insecure_cryptography = EvidenceEntry(
            False, "no_encodes_data_using_insecure_cryptography_hits"
        )
        self.utilizes_insecure_cryptography = EvidenceEntry(False, "no_utilizes_insecure_cryptography_hits")
        self.pbkdf2_iteration_count_below_10k = EvidenceEntry(False, "no_pbkdf2_iteration_count_below_10k_hits")
        self.hardcoded_api_keys_in_bundle = EvidenceEntry(False, "no_hardcoded_api_keys_in_bundle_hits")
        self.insecure_entitlements = EvidenceEntry(False, "no_insecure_entitlements_hits")
