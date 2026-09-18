"""Section-scoped OpenGrep orchestration for iOS rules."""

from __future__ import annotations

import json
import tempfile
from pathlib import Path
from typing import Any

from adapters.scanners.common import OpenGrepScanner
from adapters.scanners.ios.rule_inventory import (
    IOSRuleFile,
    IOSRuleInventory,
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
                inventory=inventory,
                rule_file=rule_file,
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
        inventory: IOSRuleInventory,
        rule_file: IOSRuleFile,
        scan_paths: list[Path],
    ) -> tuple[dict[str, Any], list[dict[str, Any]], list[dict[str, Any]], str]:
        section = rule_file.section
        metadata: dict[str, Any] = {
            "status": "failed",
            "rules_path": str(rule_file.path),
            "scan_paths": [str(path) for path in scan_paths],
            "configured_rule_ids": [],
            "attempted_rule_ids": list(rule_file.rule_ids),
            "successful_rule_ids": [],
            "failed_rule_ids": [],
        }
        result = OpenGrepScanner(rules_path=rule_file.path, scan_paths=scan_paths).scan(config)[0]
        outer_report = self._report_payload(result.raw_output)
        report = self._execution_report(outer_report)
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

        findings = self._tag_findings(report.get("results"), section)
        errors = self._tag_errors(report.get("errors"), section)
        if result.success:
            metadata["status"] = "success"
            metadata["successful_rule_ids"] = sorted(set(configured_rule_ids) or set(rule_file.rule_ids))
            return metadata, findings, errors, tool_version

        reason = result.error_message or str(outer_report.get("error", "")).strip()
        errors.insert(0, self._section_error(section, outer_report, reason))
        failed_rule_ids = self._failed_rule_ids(report, rule_file.rule_ids)
        if not failed_rule_ids:
            metadata["reason"] = reason
            return metadata, findings, errors, tool_version

        metadata["failed_rule_ids"] = sorted(failed_rule_ids)
        successful_rule_ids = set(rule_file.rule_ids) - failed_rule_ids
        retry_failed_rule_ids: set[str] = set()
        with tempfile.TemporaryDirectory(prefix="phoenix_ios_rule_") as temporary_directory:
            for rule_id in sorted(failed_rule_ids):
                try:
                    single_rule_path = inventory.write_single_rule(rule_id, Path(temporary_directory))
                except IOSRuleInventoryError as exc:
                    retry_failed_rule_ids.add(rule_id)
                    errors.append(self._rule_error(section, rule_id, outer_report, str(exc)))
                    continue

                retry_result = OpenGrepScanner(
                    rules_path=single_rule_path,
                    scan_paths=scan_paths,
                ).scan(config)[0]
                retry_outer_report = self._report_payload(retry_result.raw_output)
                retry_report = self._execution_report(retry_outer_report)
                retry_metadata = retry_report.get("scan_metadata")
                if isinstance(retry_metadata, dict):
                    retry_version = str(retry_metadata.get("tool_version", "")).strip()
                    if retry_version:
                        tool_version = retry_version
                findings.extend(self._tag_findings(retry_report.get("results"), section))
                errors.extend(self._tag_errors(retry_report.get("errors"), section))
                if retry_result.success:
                    successful_rule_ids.add(rule_id)
                    configured_retry_ids = (
                        retry_metadata.get("configured_rule_ids") if isinstance(retry_metadata, dict) else None
                    )
                    if isinstance(configured_retry_ids, list):
                        configured_rule_ids.extend(str(value) for value in configured_retry_ids if str(value).strip())
                    elif rule_id not in configured_rule_ids:
                        configured_rule_ids.append(rule_id)
                else:
                    retry_failed_rule_ids.add(rule_id)
                    retry_reason = retry_result.error_message or str(retry_outer_report.get("error", "")).strip()
                    errors.append(self._rule_error(section, rule_id, retry_outer_report, retry_reason))

        metadata["successful_rule_ids"] = sorted(successful_rule_ids)
        metadata["failed_rule_ids"] = sorted(retry_failed_rule_ids)
        metadata["configured_rule_ids"] = sorted(set(configured_rule_ids) | successful_rule_ids)
        metadata["reason"] = reason
        if successful_rule_ids:
            metadata["status"] = "partial"
        return metadata, findings, errors, tool_version

    @staticmethod
    def _execution_report(report: dict[str, Any]) -> dict[str, Any]:
        nested_report = report.get("raw_output")
        return nested_report if isinstance(nested_report, dict) else report

    @staticmethod
    def _failed_rule_ids(report: dict[str, Any], rule_ids: tuple[str, ...]) -> set[str]:
        known_rule_ids = set(rule_ids)
        return {
            str(error["rule_id"])
            for error in report.get("errors", [])
            if isinstance(error, dict) and str(error.get("rule_id", "")) in known_rule_ids
        }

    @staticmethod
    def _tag_findings(raw_findings: Any, section: IOSRuleSection) -> list[dict[str, Any]]:
        if not isinstance(raw_findings, list):
            return []
        return [
            {**finding, "phoenix_scope": section.name.lower()} for finding in raw_findings if isinstance(finding, dict)
        ]

    @staticmethod
    def _tag_errors(raw_errors: Any, section: IOSRuleSection) -> list[dict[str, Any]]:
        if not isinstance(raw_errors, list):
            return []
        return [{**error, "section": section.name.lower()} for error in raw_errors if isinstance(error, dict)]

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

    @classmethod
    def _rule_error(
        cls,
        section: IOSRuleSection,
        rule_id: str,
        report: dict[str, Any],
        reason: str,
    ) -> dict[str, Any]:
        error = cls._section_error(section, report, reason)
        error["rule_id"] = rule_id
        return error

    @staticmethod
    def _aggregate_status(sections: dict[str, dict[str, Any]]) -> str:
        statuses = [metadata["status"] for metadata in sections.values()]
        if statuses and all(status == "success" for status in statuses):
            return "complete"
        if any(status in {"success", "partial"} for status in statuses):
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
