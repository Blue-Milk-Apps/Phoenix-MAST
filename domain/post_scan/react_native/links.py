"""Build embedded Android and iOS link projections for React Native reports."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from domain.post_scan.react_native.scan_extraction_context import ReactNativeScanExtractionContext


@dataclass
class ReactNativeDeepLinks:
    deep_links: list[dict[str, Any]] | None

    def __init__(self, context: ReactNativeScanExtractionContext) -> None:
        raw = context.android_metadata.get("deep_links")
        self.deep_links = context.android_deep_links if isinstance(raw, list) else None


@dataclass
class ReactNativeURLSchemes:
    items: list[dict[str, Any]]
    queried_schemes: list[str]
    assessed: bool

    def __init__(self, context: ReactNativeScanExtractionContext) -> None:
        raw = context.ios_metadata.get("url_schemes")
        self.assessed = isinstance(raw, dict)
        declared = context.string_list(context.ios_url_schemes.get("declared_schemes"))
        self.queried_schemes = context.string_list(context.ios_url_schemes.get("queried_schemes"))
        if not declared:
            self.items = []
            return
        self.items = [
            {
                "url_name": context.first_non_empty(
                    context.ios_identity.get("display_name"),
                    context.ios_identity.get("bundle_name"),
                    context.identity.get("display_name"),
                    context.identity.get("package_name"),
                    context.project_path.name,
                ),
                "schemes": declared,
            }
        ]
