"""Build default iOS IPA binary evidence section."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass
class IOSIPABinaryEvidence:
    nx: bool = False
    pie: bool = False
    stack_canary: bool = False
    arc: bool = False
    rpath: bool = False
    code_signature: bool = False
    encrypted: bool = False
    symbols_stripped: bool = False

    def __init__(self, loaded_outputs: dict[str, Any]) -> None:
        _ = loaded_outputs
        self.nx = False
        self.pie = False
        self.stack_canary = False
        self.arc = False
        self.rpath = False
        self.code_signature = False
        self.encrypted = False
        self.symbols_stripped = False
