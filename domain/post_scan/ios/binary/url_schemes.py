"""Build the default iOS URL schemes section."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass
class IOSURLSchemes:
    items: list[dict[str, object]]

    def __init__(self, loaded_outputs: dict[str, Any]) -> None:
        _ = loaded_outputs
        self.items = []
