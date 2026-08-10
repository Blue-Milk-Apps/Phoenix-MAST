"""Shared iOS post-scan evidence models."""

from dataclasses import dataclass


@dataclass
class EvidenceEntry:
    present: bool = False
    evidence: str = ""
