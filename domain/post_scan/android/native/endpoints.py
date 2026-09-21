"""Build native Android source endpoint details."""

from __future__ import annotations

from dataclasses import dataclass

from domain.post_scan.android.native.hardcoded_values import NativeAndroidHardcodedValues


@dataclass
class NativeAndroidEndpoints:
    items: list[dict[str, str]]

    def __init__(self, hardcoded_values: NativeAndroidHardcodedValues) -> None:
        self.items = []
        seen: set[str] = set()
        for item in hardcoded_values.urls:
            endpoint = str(item.get("url", "")).strip()
            if not endpoint or endpoint in seen:
                continue
            seen.add(endpoint)
            self.items.append(
                {
                    "endpoint": endpoint,
                    "tags": "url",
                    "ip_address": "",
                    "country": "",
                }
            )
