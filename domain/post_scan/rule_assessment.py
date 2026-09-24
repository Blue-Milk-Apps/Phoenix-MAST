"""Rule semantics and assessment outcomes derived from persisted scanner metadata."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from enum import StrEnum
from typing import Any, Mapping


class FindingType(StrEnum):
    WEAKNESS = "weakness"
    REVIEW = "review"
    CONTROL = "control"
    OBSERVATION = "observation"


@dataclass(frozen=True)
class RuleDefinition:
    """Reporting snapshot of one YAML rule; detection patterns stay in the ruleset."""

    rule_id: str
    category: str
    rule_file: str
    fingerprint: str
    severity: str
    message: str
    metadata: dict[str, Any]

    @classmethod
    def from_rule(cls, rule: Mapping[str, Any], *, category: str, rule_file: str, fingerprint: str) -> RuleDefinition:
        rule_id = rule.get("id")
        if not isinstance(rule_id, str) or not rule_id.strip():
            raise ValueError("Each rule must have a non-empty id.")
        if rule_id != rule_id.strip():
            raise ValueError("Rule IDs must not contain leading or trailing whitespace.")
        metadata = rule.get("metadata")
        if not isinstance(metadata, dict):
            raise ValueError(f"{rule_id}: metadata must be a mapping.")
        if "category" in metadata or "capability_type" in metadata:
            raise ValueError(f"{rule_id}: category and applicability belong in the file/directory structure.")
        try:
            FindingType(metadata.get("finding_type"))
        except (ValueError, TypeError) as exc:
            raise ValueError(f"{rule_id}: finding_type must be weakness, review, control, or observation.") from exc
        for field in ("title", "description", "scope", "impact"):
            if not isinstance(metadata.get(field), str) or not metadata[field].strip():
                raise ValueError(f"{rule_id}: metadata.{field} must be a non-empty string.")
        remediation = metadata.get("remediation")
        if not isinstance(remediation, dict) or not isinstance(remediation.get("guidance"), str):
            raise ValueError(f"{rule_id}: metadata.remediation.guidance must be a string.")
        resources = remediation.get("resources", [])
        if not isinstance(resources, list) or any(not isinstance(resource, dict) for resource in resources):
            raise ValueError(f"{rule_id}: metadata.remediation.resources must be a list of mappings.")
        if not isinstance(metadata.get("compliance", {}), dict):
            raise ValueError(f"{rule_id}: metadata.compliance must be a mapping.")
        severity = str(rule.get("severity", "")).lower()
        if severity not in {"critical", "high", "medium", "low", "info", "error", "warning", "inventory", "experiment"}:
            raise ValueError(f"{rule_id}: unsupported severity {severity!r}.")
        return cls(rule_id.strip(), category, rule_file, fingerprint, severity, str(rule.get("message", "")), metadata)

    def snapshot(self) -> dict[str, Any]:
        return asdict(self)


def rule_assessments(opengrep: object) -> dict[str, Any]:
    """Join catalog entries to matches without reopening rule files or interpreting IDs."""

    if not isinstance(opengrep, Mapping):
        return {"status": "not_evaluated", "reason": "OpenGrep output is unavailable.", "rules": []}
    scan = opengrep.get("scan_metadata")
    scan = scan if isinstance(scan, Mapping) else {}
    scopes = scan.get("scopes")
    sources = scopes.items() if isinstance(scopes, Mapping) else ((scan.get("platform", "ios"), scan),)
    results = opengrep.get("results")
    results = results if isinstance(results, list) else []
    assessments: list[dict[str, Any]] = []
    coverage: list[dict[str, Any]] = []
    for platform, source in sources:
        if not isinstance(source, Mapping):
            continue
        catalog = source.get("rule_catalog")
        if not isinstance(catalog, list):
            continue
        outcomes = source.get("rule_execution", {})
        coverage.append(
            {
                "platform": platform,
                "mode": source.get("mode", scan.get("mode", "")),
                "status": source.get("status", "not_evaluated"),
                "reason": source.get("reason", ""),
                "ruleset_fingerprint": source.get("ruleset_fingerprint", ""),
            }
        )
        for definition in catalog:
            rule_id = definition["rule_id"]
            matches = [
                result
                for result in results
                if isinstance(result, dict)
                and result.get("check_id") == rule_id
                and result.get("phoenix_scope", platform) == platform
            ]
            execution = outcomes.get(rule_id, {}) if isinstance(outcomes, Mapping) else {}
            execution_status = execution.get("status", "not_evaluated")
            status = "present" if matches else "not_present" if execution_status == "success" else "not_evaluated"
            assessments.append(
                {
                    **definition,
                    "platform": platform,
                    "mode": source.get("mode", scan.get("mode", "")),
                    "status": status,
                    "execution_status": execution_status,
                    "execution_reason": execution.get("reason", ""),
                    "matches": matches,
                }
            )
    return {
        "status": scan.get("status", "not_evaluated"),
        "reason": scan.get("reason", opengrep.get("error", "")),
        "coverage": coverage,
        "rules": assessments,
    }
