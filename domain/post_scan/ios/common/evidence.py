"""Shared iOS post-scan evidence models."""

from dataclasses import dataclass


@dataclass
class EvidenceEntry:
    present: bool | None = False
    evidence: str = ""
