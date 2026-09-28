"""Endpoint inventory is supplied by OpenGrep assessments, not Python pattern matching."""

from dataclasses import dataclass
from typing import Any


@dataclass
class Endpoints:
    items: list[dict[str, str]]

    def __init__(self, loaded_outputs: dict[str, Any]) -> None:
        self.items = []
