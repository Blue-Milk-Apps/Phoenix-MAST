"""Build native Android source functionality evidence."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from domain.post_scan.android.native.scan_extraction_context import NativeAndroidScanExtractionContext
from domain.post_scan.rule_assessment import rule_assessments


@dataclass
class NativeAndroidFunctionality:
    items: dict[str, dict[str, Any]]
    assessed: bool

    def __init__(self, context: NativeAndroidScanExtractionContext) -> None:
        rules = rule_assessments(context.loaded_outputs.get("opengrep"))["rules"]
        capabilities: dict[str, list[dict[str, Any]]] = {}
        for rule in rules:
            capability = rule["metadata"].get("functionality")
            if rule["category"] == "functionality" and isinstance(capability, str) and capability.strip():
                capabilities.setdefault(capability, []).append(rule)
        self.assessed = bool(capabilities)
        self.items = {}
        for capability, definitions in capabilities.items():
            matches = [rule for rule in definitions if rule["status"] == "present"]
            present = (
                True
                if matches
                else False
                if definitions and all(rule["status"] == "not_present" for rule in definitions)
                else None
            )
            explanations = list(dict.fromkeys(rule["metadata"]["description"] for rule in matches))
            self.items[capability] = {
                "present": present,
                "explanation": " ".join(explanations)
                or (
                    f"No evaluated source rule indicated {capability.lower()} functionality."
                    if present is False
                    else "Functionality was not assessed because rule evidence was unavailable."
                ),
            }
