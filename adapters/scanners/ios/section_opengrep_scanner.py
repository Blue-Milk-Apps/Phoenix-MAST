"""Scan iOS category files together while retaining YAML metadata and coverage."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from adapters.scanners.common import OpenGrepScanner
from adapters.scanners.ios.rule_inventory import IOSRuleInventoryError, validate_ios_rule_inventory
from domain.models import ScanConfig, ScanResult, ScanType
from ports.scanner_port import ScannerPort


class IOSSectionOpenGrepScanner(ScannerPort):
    REPORT_PATH = "opengrep_results.json"

    def __init__(self, rules_directory: Path, scan_paths: list[Path] | None = None) -> None:
        self._rules_directory = rules_directory.resolve()
        self._scan_paths = [path.resolve() for path in scan_paths] if scan_paths else None

    @property
    def scan_type(self) -> ScanType:
        return ScanType.OPENGREP_SOURCE

    @property
    def name(self) -> str:
        return "iOS Category OpenGrep Scanner"

    @property
    def description(self) -> str:
        return "Metadata-driven iOS analysis using the explicitly selected rule directory."

    def is_available(self) -> bool:
        return OpenGrepScanner().is_available()

    def scan(self, config: ScanConfig) -> list[ScanResult]:
        paths = self._scan_paths or [config.project_path.resolve()]
        metadata: dict[str, Any] = {
            "status": "failed",
            "platform": "ios",
            "mode": config.mode.lower(),
            "rules_path": str(self._rules_directory),
            "scan_paths": [str(path) for path in paths],
            "rule_catalog": [],
            "rule_execution": {},
            "configured_rule_ids": [],
            "sections": {},
        }
        findings: list[dict[str, Any]] = []
        errors: list[dict[str, Any]] = []
        try:
            # The execution flag selects the mode. Reject accidental cross-mode overrides.
            if self._rules_directory.name in {"source", "binary"} and self._rules_directory.name != config.mode.lower():
                raise IOSRuleInventoryError("The selected rules directory conflicts with the execution mode.")
            inventory = validate_ios_rule_inventory(self._rules_directory)
            metadata["rule_catalog"] = inventory.catalog
            metadata["ruleset_fingerprint"] = inventory.fingerprint
            metadata["configured_rule_ids"] = sorted(item["rule_id"] for item in inventory.catalog)
            result = OpenGrepScanner(rules_paths=[item.path for item in inventory.files], scan_paths=paths).scan(
                config
            )[0]
            try:
                outer = json.loads(result.raw_output)
                payload = outer.get("raw_output", outer) if isinstance(outer, dict) else {}
                if not isinstance(payload, dict) or not isinstance(payload.get("results"), list):
                    raise ValueError("OpenGrep did not return a findings list.")
            except (ValueError, TypeError):
                payload = {"results": [], "errors": [{"message": "Invalid or missing OpenGrep JSON output."}]}
            scan_errors = payload.get("errors") or []
            tool_metadata = payload.get("scan_metadata") or {}
            metadata["tool_version"] = tool_metadata.get("tool_version", "")
            scanned = (payload.get("paths") or {}).get("scanned")
            complete = result.success and payload.get("success") is not False and not scan_errors and scanned != []
            status = "success" if complete else "not_evaluated"
            reason = (
                ""
                if complete
                else result.error_message
                or ("No eligible files were scanned." if scanned == [] else "OpenGrep execution was incomplete.")
            )
            categories = {item["rule_id"]: item["category"] for item in inventory.catalog}
            findings.extend(
                {**finding, "phoenix_scope": "ios", "phoenix_category": categories.get(finding.get("check_id"), "")}
                for finding in payload["results"]
                if isinstance(finding, dict)
            )
            errors.extend({"detail": error} for error in scan_errors)
            if not complete:
                errors.append({"message": reason})
            # A shared run cannot certify clean results for any category when incomplete.
            for rule_file in inventory.files:
                section = {
                    "status": status,
                    "reason": reason,
                    "configured_rule_ids": list(rule_file.rule_ids),
                    "successful_rule_ids": list(rule_file.rule_ids) if complete else [],
                    "scan_paths": [str(path) for path in paths],
                }
                metadata["sections"][rule_file.path.name] = section
                for rule_id in rule_file.rule_ids:
                    metadata["rule_execution"][rule_id] = {"status": status, "reason": reason}
            metadata["status"] = "success" if complete else ("partial" if findings else "failed")
            if metadata["status"] != "success":
                metadata["reason"] = reason
        except IOSRuleInventoryError as exc:
            metadata["reason"] = str(exc)
            errors.append({"message": str(exc)})
        success = metadata["status"] in {"success", "partial"}
        return [
            ScanResult(
                scanner_name=self.name,
                scan_type=self.scan_type,
                success=success,
                error_message="" if success else metadata.get("reason", "No iOS rule file completed successfully."),
                raw_output=json.dumps(
                    {"results": findings, "errors": errors, "success": success, "scan_metadata": metadata},
                    indent=2,
                    sort_keys=True,
                ),
                relative_target_path=self.REPORT_PATH,
                description=self.description,
            )
        ]
