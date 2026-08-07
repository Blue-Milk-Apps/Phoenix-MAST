"""Build the default iOS hardcoded values section."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass
class IOSHardcodedValues:
    urls: list[dict[str, str]]
    emails: list[str]
    secrets: list[dict[str, str]]

    def __init__(self, loaded_outputs: dict[str, Any]) -> None:
        _ = loaded_outputs
        self.urls = []
        self.emails = []
        self.secrets = []
