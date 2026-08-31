"""Preserve raw-only Flutter and embedded-platform findings for manual review."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from domain.post_scan.android.rule_registry import (
    ANDROID_RULE_REGISTRY,
    AndroidRuleDisposition,
)
from domain.post_scan.flutter.rule_registry import (
    FLUTTER_RULE_REGISTRY,
    FlutterRuleDisposition,
)
from domain.post_scan.flutter.scan_extraction_context import FlutterScanExtractionContext
from domain.post_scan.flutter.security_evidence import opengrep_scope_applicable
from domain.post_scan.ios.rule_registry import IOS_RULE_REGISTRY, IOSRuleDisposition


@dataclass(frozen=True)
class FlutterManualReviewFinding:
    rule_id: str
    scope: str
    severity: str
    reason: str
    location: str
    message: str


@dataclass
class FlutterManualReviewInventory:
    findings: list[FlutterManualReviewFinding]
    assessed_scopes: list[str]
    assessed: bool
    fully_assessed: bool

    def __init__(self, context: FlutterScanExtractionContext) -> None:
        raw_rules = self._raw_rules()
        applicable_scopes = [
            scope for scope, rules in raw_rules.items() if rules and opengrep_scope_applicable(context, scope)
        ]
        self.assessed_scopes = [
            scope
            for scope in applicable_scopes
            if context.opengrep_scope_assessed(scope)
            and frozenset(raw_rules[scope]) <= context.opengrep_configured_rule_ids(scope)
        ]
        self.assessed = bool(self.assessed_scopes)
        self.fully_assessed = bool(applicable_scopes) and len(self.assessed_scopes) == len(applicable_scopes)

        findings: list[FlutterManualReviewFinding] = []
        for scope in applicable_scopes:
            for result in context.opengrep_results_for_scope(scope):
                rule_id = context.first_non_empty(result.get("check_id"))
                rule = raw_rules[scope].get(rule_id)
                if rule is None:
                    continue
                findings.append(
                    FlutterManualReviewFinding(
                        rule_id=rule_id,
                        scope=scope,
                        severity=context.first_non_empty(getattr(rule, "severity", ""), "Info"),
                        reason=context.first_non_empty(getattr(rule, "reason", "")),
                        location=self._location(context, result),
                        message=self._message(context, result),
                    )
                )
        self.findings = list(dict.fromkeys(findings))

    @staticmethod
    def _raw_rules() -> dict[str, dict[str, object]]:
        return {
            "flutter": {
                rule_id: mapping
                for rule_id, mapping in FLUTTER_RULE_REGISTRY.items()
                if mapping.disposition is FlutterRuleDisposition.RAW_ONLY
            },
            "android": {
                rule_id: mapping
                for rule_id, mapping in ANDROID_RULE_REGISTRY.items()
                if mapping.disposition is AndroidRuleDisposition.RAW_ONLY
            },
            "ios": {
                rule_id: mapping
                for rule_id, mapping in IOS_RULE_REGISTRY.items()
                if mapping.disposition is IOSRuleDisposition.RAW_ONLY
            },
        }

    @staticmethod
    def _location(
        context: FlutterScanExtractionContext,
        result: dict[str, Any],
    ) -> str:
        path_text = context.first_non_empty(result.get("path"))
        if path_text:
            path = Path(path_text)
            if path.is_absolute():
                try:
                    path_text = path.relative_to(context.project_path).as_posix()
                except ValueError:
                    path_text = path.as_posix()
        start = result.get("start")
        start = start if isinstance(start, dict) else {}
        line = start.get("line")
        return f"{path_text}:{line}" if path_text and line not in (None, "") else path_text

    @staticmethod
    def _message(
        context: FlutterScanExtractionContext,
        result: dict[str, Any],
    ) -> str:
        extra = result.get("extra")
        extra = extra if isinstance(extra, dict) else {}
        metadata = extra.get("metadata")
        metadata = metadata if isinstance(metadata, dict) else {}
        phoenix = metadata.get("phoenix")
        phoenix = phoenix if isinstance(phoenix, dict) else {}
        return context.first_non_empty(
            phoenix.get("description"),
            phoenix.get("title"),
            extra.get("message"),
            extra.get("lines"),
            result.get("check_id"),
        )
