"""Build discovered Android endpoints for post-scan reports."""

from dataclasses import dataclass
from typing import Any

from domain.post_scan.utilities import first_non_empty


@dataclass
class EndpointsBuilder:
    items: list[dict[str, str]]

    def __init__(self, loaded_outputs: dict[str, Any]) -> None:
        self.items = []
        seen: set[str] = set()
        for item in (loaded_outputs.get("apktool_secrets_endpoints") or {}).get("items") or []:
            category = str((item.get("context") or {}).get("category", "")).strip().lower()
            value = first_non_empty(item.get("value"))
            if category not in {"url", "domain"} or not value or f"{category}:{value}" in seen:
                continue
            seen.add(f"{category}:{value}")
            self.items.append({"endpoint": value, "tags": category, "ip_address": "", "country": ""})
