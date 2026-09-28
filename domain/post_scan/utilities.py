from typing import Any

from domain.report.models import SecretFindingSummary, SecretScanSummary


def summarize_secret_scans(loaded_outputs: dict[str, Any]) -> tuple[SecretScanSummary, ...]:
    """Summarize scanner findings without copying credential values into reports."""
    summaries = []
    project = str((loaded_outputs.get("scan_metadata") or {}).get("project_path", "")).rstrip("/")
    for scanner, key, filename in (
        ("TruffleHog", "trufflehog_outputs", "trufflehog_results.json"),
        ("Gitleaks", "gitleaks_outputs", "gitleaks_report.json"),
    ):
        outputs = loaded_outputs.get(key)
        outputs = outputs if isinstance(outputs, dict) else {}
        payload = outputs.get(filename, outputs.get("scan_summary.json"))
        status = "Completed"
        reason = ""
        if isinstance(payload, dict):
            reason = str(payload.get("error") or "Scanner output was incomplete.")
            status = "Unavailable" if payload.get("skipped") else "Failed"
            payload = payload.get("raw_output")
        if not isinstance(payload, list):
            summaries.append(
                SecretScanSummary(
                    scanner,
                    status if status != "Completed" else "Unavailable",
                    reason=reason or "No readable scanner results were recorded.",
                )
            )
            continue
        findings = []
        malformed = False
        for item in payload:
            if not isinstance(item, dict):
                malformed = True
                continue
            detector = item.get("DetectorName") if scanner == "TruffleHog" else item.get("RuleID")
            if not isinstance(detector, str) or not detector.strip():
                malformed = True
                continue
            if scanner == "TruffleHog":
                source = item.get("SourceMetadata") or {}
                source = source.get("Data", {}) if isinstance(source, dict) else {}
                source = source.get("Filesystem", {}) if isinstance(source, dict) else {}
                path = str(source.get("file") or "") if isinstance(source, dict) else ""
                line = source.get("line") if isinstance(source, dict) else None
                verification = "Verified" if item.get("Verified") is True else "Unverified"
            else:
                path = str(item.get("File") or "")
                line = item.get("StartLine")
                verification = "Not checked"
            if project and path.startswith(project + "/"):
                path = path[len(project) + 1 :]
            location = f"{path}:{line}" if path and line is not None else path or "Location unavailable"
            findings.append(SecretFindingSummary(str(detector), location, verification))
        if malformed:
            status = "Failed"
            reason = "Some scanner records could not be interpreted."
        if status != "Completed" and findings:
            status = "Partial"
        summaries.append(SecretScanSummary(scanner, status, tuple(findings), reason))
    return tuple(summaries)


def first_non_empty(*values: object) -> str:
    for value in values:
        if value is not None:
            text = str(value).strip()
            if text:
                return text
    return ""


def coerce_bool_like(value: object) -> bool | None:
    text = str(value).strip().lower() if value is not None else ""
    if text in {"true", "1", "yes"}:
        return True
    if text in {"false", "0", "no"}:
        return False
    return None


def secret_values(loaded_outputs: dict[str, Any]) -> dict[str, Any]:
    """Display detector names and locations without credential values."""
    return {
        "urls": [],
        "emails": [],
        "secrets": [
            {"value": f"{finding.detector} credential (redacted)", "location": finding.location}
            for summary in summarize_secret_scans(loaded_outputs)
            for finding in summary.findings
        ],
    }
