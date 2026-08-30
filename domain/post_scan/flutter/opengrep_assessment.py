"""Tri-state assessment of Flutter OpenGrep evidence."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from domain.post_scan.flutter.rule_registry import REPORT_RULE_IDS_BY_SECTION


@dataclass(frozen=True)
class FlutterRuleAssessment:
    present: bool | None
    evidence: str = ""
    details: list[str] = field(default_factory=list)


class FlutterOpenGrepAssessment:
    """Assess findings only when the exact mapped Flutter rules ran successfully."""

    def __init__(self, report: object) -> None:
        self.report = report if isinstance(report, dict) else {}

    def assess_evidence(self, section: str, evidence_key: str) -> FlutterRuleAssessment:
        rule_ids = REPORT_RULE_IDS_BY_SECTION.get(section, {}).get(evidence_key)
        if not rule_ids:
            return FlutterRuleAssessment(None)

        matches = [
            self._finding_evidence(finding)
            for finding in self._findings()
            if self._finding_scope(finding) == "flutter" and str(finding.get("check_id", "")).strip() in rule_ids
        ]
        matches = list(dict.fromkeys(item for item in matches if item))
        if matches:
            return FlutterRuleAssessment(True, "; ".join(matches[:5]), matches[:10])
        if self.rules_assessed(rule_ids, scope="flutter"):
            return FlutterRuleAssessment(False, f"no_{evidence_key}_hits", [])
        return FlutterRuleAssessment(None)

    def rules_assessed(self, rule_ids: frozenset[str], *, scope: str) -> bool:
        scope_metadata = self._scope_metadata(scope)
        if scope_metadata.get("status") != "success":
            return False
        configured = scope_metadata.get("configured_rule_ids")
        if not isinstance(configured, list):
            return False
        configured_ids = {str(rule_id).strip() for rule_id in configured if str(rule_id).strip()}
        return set(rule_ids) <= configured_ids

    def _findings(self) -> list[dict[str, Any]]:
        findings = self.report.get("results")
        if not isinstance(findings, list):
            return []
        return [finding for finding in findings if isinstance(finding, dict)]

    def _scope_metadata(self, scope: str) -> dict[str, Any]:
        metadata = self.report.get("scan_metadata")
        metadata = metadata if isinstance(metadata, dict) else {}
        scopes = metadata.get("scopes")
        scopes = scopes if isinstance(scopes, dict) else {}
        scope_metadata = scopes.get(scope)
        return scope_metadata if isinstance(scope_metadata, dict) else {}

    @staticmethod
    def _finding_scope(finding: dict[str, Any]) -> str:
        explicit = str(finding.get("phoenix_scope", "")).strip()
        if explicit:
            return explicit
        rule_id = str(finding.get("check_id", "")).strip()
        return "flutter" if rule_id.startswith("flutter.") else ""

    def _finding_evidence(self, finding: dict[str, Any]) -> str:
        path_text = str(finding.get("path", "")).strip()
        path = self._relative_path(path_text)
        start = finding.get("start")
        start = start if isinstance(start, dict) else {}
        line = start.get("line")
        location = f"{path}:{line}" if path and line not in (None, "") else path
        extra = finding.get("extra")
        extra = extra if isinstance(extra, dict) else {}
        message = str(extra.get("message", "")).strip()
        if location and message:
            return f"{location}: {message}"
        return location or message or str(finding.get("check_id", "")).strip()

    def _relative_path(self, value: str) -> str:
        if not value:
            return ""
        path = Path(value)
        if not path.is_absolute():
            return path.as_posix()
        metadata = self.report.get("scan_metadata")
        metadata = metadata if isinstance(metadata, dict) else {}
        project_path = Path(str(metadata.get("project_path", "")))
        try:
            return path.relative_to(project_path).as_posix()
        except ValueError:
            return path.as_posix()
