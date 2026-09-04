"""Tri-state React Native OpenGrep assessment."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from domain.post_scan.react_native.scan_extraction_context import ReactNativeScanExtractionContext


@dataclass(frozen=True)
class ReactNativeRuleAssessment:
    present: bool | None
    evidence: str = ""
    details: list[str] = field(default_factory=list)


class ReactNativeOpenGrepAssessment:
    def __init__(self, context: ReactNativeScanExtractionContext) -> None:
        self.context = context

    def assess(self, scope: str, rule_ids: frozenset[str], evidence_key: str) -> ReactNativeRuleAssessment:
        matches = [
            self._evidence(item)
            for item in self.context.opengrep_results_for_scope(scope)
            if self.context.first_non_empty(item.get("check_id")) in rule_ids
        ]
        matches = list(dict.fromkeys(item for item in matches if item))
        if matches:
            return ReactNativeRuleAssessment(True, "; ".join(matches[:5]), matches[:10])
        if self.context.opengrep_scope_assessed(scope, rule_ids):
            return ReactNativeRuleAssessment(False, f"no_{evidence_key}_{scope}_hits", [])
        return ReactNativeRuleAssessment(None)

    def _evidence(self, finding: dict[str, object]) -> str:
        path_text = self.context.first_non_empty(finding.get("path"))
        if path_text:
            path = Path(path_text)
            if path.is_absolute():
                try:
                    path_text = path.relative_to(self.context.project_path).as_posix()
                except ValueError:
                    path_text = path.as_posix()
        start = finding.get("start")
        line = start.get("line") if isinstance(start, dict) else None
        return f"{path_text}:{line}" if path_text and line not in (None, "") else path_text
