"""Build Android deep-link details for post-scan reports."""

from dataclasses import dataclass
from typing import Any


@dataclass
class DeepLinks:
    deep_links: list[dict[str, Any]]

    def __init__(self, loaded_outputs: dict[str, Any]) -> None:
        deep_links = (loaded_outputs.get("apktool_deep_links") or {}).get("deep_links")
        self.deep_links = deep_links if isinstance(deep_links, list) else []
