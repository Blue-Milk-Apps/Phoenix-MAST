"""Build native iOS URL schemes from source plists."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from domain.post_scan.ios.native_scan_extraction_context import NativeIOSScanExtractionContext


@dataclass
class NativeIOSURLSchemes:
    items: list[dict[str, Any]]

    def __init__(self, context: NativeIOSScanExtractionContext) -> None:
        self.items = []
        for path, document in context.plist_outputs.items():
            schemes = document.get("url_schemes")
            if not isinstance(schemes, dict):
                continue
            declared = context.string_list(schemes.get("declared_schemes"))
            if not declared:
                continue
            app_meta = document.get("app_meta") or {}
            self.items.append(
                {
                    "url_name": context.first_non_empty(
                        app_meta.get("display_name"),
                        app_meta.get("bundle_name"),
                        path,
                    ),
                    "schemes": declared,
                }
            )
