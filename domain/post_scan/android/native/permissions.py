"""Build native Android source permission details."""

from __future__ import annotations

from dataclasses import dataclass

from domain.post_scan.android.native.scan_extraction_context import NativeAndroidScanExtractionContext
from domain.post_scan.android.permissions import Permissions


@dataclass
class NativeAndroidPermissions:
    items: list[dict[str, str]]

    def __init__(self, context: NativeAndroidScanExtractionContext) -> None:
        self.items = []
        seen: set[str] = set()
        for permission in context.permissions:
            name = context.first_non_empty(permission.get("name"))
            if not name or name in seen:
                continue
            seen.add(name)
            self.items.append(
                {
                    "permission": name,
                    "status": "",
                    "info": "",
                    "usage_description": "",
                    "general_description": self._description(name),
                }
            )

    @staticmethod
    def _description(name: str) -> str:
        description = Permissions.ANDROID_PERMISSION_DESCRIPTIONS.get(name)
        if description:
            return description
        suffix = name.rsplit(".", 1)[-1].replace("_", " ").lower()
        return suffix[:1].upper() + suffix[1:] + "." if suffix else ""
