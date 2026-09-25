"""Build native Android source permission details."""

from __future__ import annotations

from dataclasses import dataclass

from domain.post_scan.android.native.scan_extraction_context import NativeAndroidScanExtractionContext
from domain.post_scan.rule_assessment import rule_assessments


@dataclass
class NativeAndroidPermissions:
    items: list[dict[str, str]]

    def __init__(self, context: NativeAndroidScanExtractionContext) -> None:
        self.items = []
        seen: set[str] = set()
        for rule in rule_assessments(context.loaded_outputs.get("opengrep"))["rules"]:
            if rule["category"] != "functionality" or rule["metadata"]["scope"] != "app_declaration":
                continue
            for match in rule["matches"]:
                capture = ((match.get("extra") or {}).get("metavars") or {}).get("$PERMISSION") or {}
                name = str(capture.get("abstract_content") or "").strip()
                if not name or name in seen:
                    continue
                seen.add(name)
                self.items.append(
                    {
                        "permission": name,
                        "status": "",
                        "info": "",
                        "usage_description": "",
                        "general_description": f"The app declares the {name} permission.",
                    }
                )
