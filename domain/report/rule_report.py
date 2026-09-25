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
        assessment = {}
    groups: dict[str, list[SecurityCheck]] = {}
    for section in report.vulnerability_sections:
        # Preserve positive evidence even when another platform was not evaluated.
        checks = [
            replace(check, result=AssessmentStatus.PRESENT, status=AssessmentStatus.PRESENT)
            if AssessmentStatus.PRESENT in (check.result, check.status)
            else check
            for check in section.checks
        ]
        groups.setdefault(section.name.replace("_", " ").title(), []).extend(checks)
    for rule in assessment.get("rules", ()):
        metadata = rule["metadata"]
        platform = ReportPlatform(rule["platform"])
        category = str(rule["category"])
        if category == "functionality":
            continue
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
            text = str(extra.get("lines") or "").strip()
            evidence.append(f"{location}: {text}".strip(": "))
        execution = rule["execution_status"]
        explanation = metadata["description"]
        if status == AssessmentStatus.PRESENT and execution != "success":
            explanation += " Matches were retained from an incomplete scan."
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
        label = category.replace("_", " ").title()
        if platform != report.metadata.target.platform:
            platform_label = "iOS" if platform == ReportPlatform.IOS else platform.value.replace("_", " ").title()
            label = f"{platform_label} / {label}"
        groups.setdefault(label, []).append(check)
    sections = []
    evaluations = []
    summaries = []
    counts = dict.fromkeys(("critical", "high", "medium", "low", "info", "secure"), 0)
    for label, checks in groups.items():
        if not checks or label.rsplit("/", 1)[-1].strip().casefold() == "functionality":
            continue
        matches = tuple(check for check in checks if check.result == AssessmentStatus.PRESENT)
        if matches:
            sections.append(VulnerabilitySection(label, "", matches))
        weaknesses = [check for check in checks if check.finding_type in {"", "weakness"}]
        weakness_matches = [check for check in weaknesses if check.result == AssessmentStatus.PRESENT]
        for check in weakness_matches:
            if check.severity.value in counts:
                counts[check.severity.value] += 1
        risk = RiskLevel.NOT_EVALUATED
        if weakness_matches:
            risk = next(
                (
                    level
                    for level in (RiskLevel.CRITICAL, RiskLevel.HIGH, RiskLevel.MEDIUM)
                    if any(check.severity.value == level.value for check in weakness_matches)
                ),
                RiskLevel.LOW,
            )
        elif weaknesses and all(check.result == AssessmentStatus.NOT_PRESENT for check in weaknesses):
            risk = RiskLevel.LOW
        descriptions = tuple(check.name for check in weakness_matches)
        if not descriptions:
            descriptions = (
                "No weakness findings in the evaluated inputs."
                if risk == RiskLevel.LOW
                else "No confirmed weakness findings; checks are incomplete or informational only.",
            )
        evaluations.append(OverallEvaluation(label, risk, descriptions))
        summaries.append(RiskSummary(label, risk))
    return replace(
        report,
        vulnerability_sections=tuple(sections),
        overall_evaluation=tuple(evaluations),
        risk_summary=tuple(summaries),
        findings_severity=FindingSeverity(**counts),
        rule_coverage=tuple(assessment.get("coverage", ())),
        rule_status=str(assessment.get("status", "")),
        rule_status_reason=str(assessment.get("reason", "")),
    )


def _compliance(value: Mapping[str, Any]) -> str:
    rows = []
    for framework, entries in value.items():
        if not isinstance(entries, list):
            entries = [entries]
        for entry in entries:
            control = str(entry.get("id", "") if isinstance(entry, Mapping) else entry).strip()
            if control:
                rows.append(f"{framework.replace('_', ' ').upper()}: {control}")
    return "\n".join(dict.fromkeys(rows))
