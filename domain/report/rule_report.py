"""Compose report checks directly from persisted rule definitions and outcomes."""

from __future__ import annotations

from dataclasses import replace
from typing import Any, Mapping

from domain.report.models import (
    AssessmentStatus,
    CheckSeverity,
    FindingSeverity,
    OverallEvaluation,
    PlatformAssessment,
    ReportData,
    ReportPlatform,
    RiskLevel,
    RiskSummary,
    SecurityCheck,
    VulnerabilitySection,
)


def with_rule_assessments(report: ReportData, data: Mapping[str, Any]) -> ReportData:
    assessment = data.get("rule_assessments")
    if not isinstance(assessment, Mapping):
        return report
    if (
        not assessment.get("coverage")
        and not assessment.get("rules")
        and report.metadata.target.platform != ReportPlatform.IOS
    ):
        return report
    groups: dict[tuple[str, str], list[SecurityCheck]] = {}
    for rule in assessment.get("rules", ()):
        metadata = rule["metadata"]
        platform = ReportPlatform(rule["platform"])
        category = str(rule["category"])
        status = AssessmentStatus(rule["status"])
        severity = {"error": "high", "warning": "medium", "inventory": "info", "experiment": "info"}.get(
            rule["severity"], rule["severity"]
        )
        evidence = []
        for match in rule["matches"]:
            extra = match.get("extra") or {}
            path = str(match.get("path", ""))
            line = (match.get("start") or {}).get("line")
            location = f"{path}:{line}" if line is not None else path
            text = str(extra.get("lines") or extra.get("message") or "").strip()
            evidence.append(f"{location}: {text}".strip(": "))
        execution = rule["execution_status"]
        if status == AssessmentStatus.PRESENT:
            explanation = metadata["description"]
            if execution != "success":
                explanation += " Matches were retained from an incomplete scan."
        elif status == AssessmentStatus.NOT_PRESENT:
            explanation = "No matches were found in the inputs evaluated by this rule."
        else:
            explanation = rule.get("execution_reason") or "This rule was not evaluated successfully."
        remediation = metadata.get("remediation", {})
        references = [
            str(resource["url"])
            for resource in remediation.get("resources", ())
            if isinstance(resource, Mapping) and resource.get("url")
        ]
        if metadata.get("reference"):
            references.append(str(metadata["reference"]))
        check = SecurityCheck(
            name=metadata["title"],
            severity=CheckSeverity(severity),
            result=status,
            explanation=explanation,
            evidence="\n".join(dict.fromkeys(evidence)),
            compliance=_compliance(metadata.get("compliance", {})),
            platform_assessments=(PlatformAssessment(platform, status, explanation, tuple(evidence)),),
            rule_id=rule["rule_id"],
            finding_type=metadata["finding_type"],
            scope=metadata["scope"],
            impact=metadata["impact"],
            remediation=remediation.get("guidance", ""),
            references=tuple(dict.fromkeys(references)),
            execution_status=execution,
            rule_file=rule["rule_file"],
        )
        groups.setdefault((platform.value, category), []).append(check)
    sections = []
    evaluations = []
    summaries = []
    counts = {
        key: getattr(report.findings_severity, key) for key in ("critical", "high", "medium", "low", "info", "secure")
    }
    for (platform, category), checks in sorted(groups.items()):
        platform_label = "iOS" if platform == "ios" else platform.replace("_", " ").title()
        label = f"{platform_label} / {category.replace('_', ' ').title()}"
        sections.append(
            VulnerabilitySection(
                label, "Rule outcomes are limited to each check's stated evidence scope.", tuple(checks)
            )
        )
        weaknesses = [check for check in checks if check.finding_type == "weakness"]
        matches = [check for check in weaknesses if check.result == AssessmentStatus.PRESENT]
        for check in matches:
            counts[check.severity.value] += 1
        risk = RiskLevel.NOT_EVALUATED
        if matches:
            risk = next(
                (
                    level
                    for level in (RiskLevel.CRITICAL, RiskLevel.HIGH, RiskLevel.MEDIUM)
                    if any(check.severity.value == level.value for check in matches)
                ),
                RiskLevel.LOW,
            )
        elif weaknesses and all(check.execution_status == "success" for check in weaknesses):
            risk = RiskLevel.LOW
        descriptions = tuple(check.name for check in matches) or (
            "No matching weaknesses in the evaluated inputs."
            if risk == RiskLevel.LOW
            else "Weakness coverage is incomplete or this category contains only review, control, or observation rules.",
        )
        evaluations.append(OverallEvaluation(label, risk, descriptions))
        summaries.append(RiskSummary(label, risk))
    return replace(
        report,
        vulnerability_sections=report.vulnerability_sections + tuple(sections),
        overall_evaluation=report.overall_evaluation + tuple(evaluations),
        risk_summary=report.risk_summary + tuple(summaries),
        findings_severity=FindingSeverity(**counts),
        rule_coverage=tuple(assessment.get("coverage", ())),
        rule_status=str(assessment.get("status", "not_evaluated")),
        rule_status_reason=str(assessment.get("reason", "")),
    )


def _compliance(value: Mapping[str, Any]) -> str:
    rows = []
    for framework, entries in value.items():
        if not isinstance(entries, list):
            entries = [entries]
        labels = []
        for entry in entries:
            if isinstance(entry, Mapping):
                relationship = entry.get("relationship")
                labels.append(str(entry.get("id", "")) + (f" ({relationship})" if relationship else ""))
            else:
                labels.append(str(entry))
        rows.append(f"{framework}: {', '.join(labels)}")
    return "; ".join(rows)
