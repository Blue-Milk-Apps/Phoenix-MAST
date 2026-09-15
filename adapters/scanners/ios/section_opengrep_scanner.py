"""Section-scoped OpenGrep orchestration for iOS rules."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from adapters.scanners.common import OpenGrepScanner
from adapters.scanners.ios.rule_inventory import (
    IOSRuleInventoryError,
    IOSRuleSection,
    validate_ios_rule_inventory,
)
from domain.models import ScanConfig, ScanResult, ScanType
from ports.scanner_port import ScannerPort


class IOSSectionOpenGrepScanner(ScannerPort):
    """Run each iOS rule section independently and merge its outcomes."""

    REPORT_PATH = "opengrep_results.json"

    def __init__(self, rules_directory: Path, scan_paths: list[Path] | None = None) -> None:
        self._rules_directory = rules_directory.resolve()
        self._scan_paths = [path.resolve() for path in scan_paths] if scan_paths else None

    @property
    def scan_type(self) -> ScanType:
        return ScanType.OPENGREP_SOURCE

    @property
    def name(self) -> str:
        return "iOS Sectioned OpenGrep Scanner"

    @property
    def description(self) -> str:
        return "Section-scoped iOS source and binary string analysis with OpenGrep."

    def is_available(self) -> bool:
        return OpenGrepScanner().is_available()

    def scan(self, config: ScanConfig) -> list[ScanResult]:
        scan_paths = self._scan_paths or [config.project_path.resolve()]
        try:
            inventory = validate_ios_rule_inventory(self._rules_directory)
        except IOSRuleInventoryError as exc:
            return [self._failure(str(exc), scan_paths)]

        sections: dict[str, dict[str, Any]] = {}
        findings: list[dict[str, Any]] = []
        errors: list[dict[str, Any]] = []
        configured_rule_ids: set[str] = set()
        tool_versions: set[str] = set()

        for rule_file in inventory.files:
            metadata, section_findings, section_errors, tool_version = self._scan_section(
                config,
                section=rule_file.section,
                rules_path=rule_file.path,
                scan_paths=scan_paths,
            )
            sections[rule_file.section.name.lower()] = metadata
            findings.extend(section_findings)
            errors.extend(section_errors)
            configured_rule_ids.update(metadata["configured_rule_ids"])
            if tool_version:
                tool_versions.add(tool_version)

        status = self._aggregate_status(sections)
        success = status != "failed"
        payload = {
            "results": findings,
            "errors": errors,
            "success": success,
            "scan_metadata": {
                "status": status,
                "tool": "opengrep",
                "tool_version": ", ".join(sorted(tool_versions)),
                "scanner_name": self.name,
                "scan_type": self.scan_type.value,
                "project_path": str(scan_paths[0]),
                "scan_paths": [str(path) for path in scan_paths],
                "rules_path": str(self._rules_directory),
                "configured_rule_ids": sorted(configured_rule_ids),
                "sections": sections,
            },
        }
        return [
            ScanResult(
                scanner_name=self.name,
                scan_type=self.scan_type,
                success=success,
                error_message="No iOS OpenGrep section completed successfully." if not success else "",
                raw_output=json.dumps(payload, indent=2, sort_keys=True),
                relative_target_path=self.REPORT_PATH,
                description=self.description,
            )
        ]

    def _scan_section(
        self,
        config: ScanConfig,
        *,
        section: IOSRuleSection,
        rules_path: Path,
        scan_paths: list[Path],
    ) -> tuple[dict[str, Any], list[dict[str, Any]], list[dict[str, Any]], str]:
        metadata: dict[str, Any] = {
            "status": "failed",
            "rules_path": str(rules_path),
            "scan_paths": [str(path) for path in scan_paths],
            "configured_rule_ids": [],
        }
        result = OpenGrepScanner(rules_path=rules_path, scan_paths=scan_paths).scan(config)[0]
        report = self._report_payload(result.raw_output)
        report_metadata = report.get("scan_metadata")
        report_metadata = report_metadata if isinstance(report_metadata, dict) else {}
        tool_version = str(report_metadata.get("tool_version", "")).strip()

        configured = report_metadata.get("configured_rule_ids")
        configured_rule_ids = sorted(
            {str(rule_id).strip() for rule_id in configured if str(rule_id).strip()}
            if isinstance(configured, list)
            else set()
        )
        metadata["configured_rule_ids"] = configured_rule_ids

        if not result.success:
            metadata["reason"] = result.error_message or str(report.get("error", "")).strip()
            return metadata, [], [self._section_error(section, report, metadata["reason"])], tool_version

        metadata["status"] = "success"
        findings = [
            {**finding, "phoenix_scope": section.name.lower()}
            for finding in report.get("results", [])
            if isinstance(finding, dict)
        ]
        errors = [
            {**error, "section": section.name.lower()} for error in report.get("errors", []) if isinstance(error, dict)
        ]
        return metadata, findings, errors, tool_version

    @staticmethod
    def _report_payload(raw_output: str) -> dict[str, Any]:
        try:
            payload = json.loads(raw_output)
        except json.JSONDecodeError:
            return {}
        return payload if isinstance(payload, dict) else {}

    @staticmethod
    def _section_error(section: IOSRuleSection, report: dict[str, Any], reason: str) -> dict[str, Any]:
        error: dict[str, Any] = {"section": section.name.lower(), "error": reason}
        for key in ("return_code", "stderr", "command"):
            if key in report:
                error[key] = report[key]
        if "raw_output" in report:
            error["stdout"] = report["raw_output"]
        return error

    @staticmethod
    def _aggregate_status(sections: dict[str, dict[str, Any]]) -> str:
        statuses = [metadata["status"] for metadata in sections.values()]
        if statuses and all(status == "success" for status in statuses):
            return "complete"
        if any(status == "success" for status in statuses):
            return "partial"
        return "failed"

    def _failure(self, error: str, scan_paths: list[Path]) -> ScanResult:
        payload = {
            "results": [],
            "errors": [{"error": error}],
            "success": False,
            "scan_metadata": {
                "status": "failed",
                "scanner_name": self.name,
                "scan_type": self.scan_type.value,
                "project_path": str(scan_paths[0]),
                "scan_paths": [str(path) for path in scan_paths],
                "rules_path": str(self._rules_directory),
                "sections": {},
            },
        }
        return ScanResult(
            scanner_name=self.name,
            scan_type=self.scan_type,
            success=False,
            error_message=error,
            raw_output=json.dumps(payload, indent=2, sort_keys=True),
            relative_target_path=self.REPORT_PATH,
            description=self.description,
        )
