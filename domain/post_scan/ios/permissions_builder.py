"""Build default iOS permissions section."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass
class IOSPermissions:
    items: list[dict[str, str]]

    def __init__(self, loaded_outputs: dict[str, Any]) -> None:
        _ = loaded_outputs
        self.items = []
