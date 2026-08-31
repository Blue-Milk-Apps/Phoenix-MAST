"""Scoped OpenGrep orchestration for Flutter source projects."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from adapters.scanners.common import OpenGrepScanner
from domain.models import ScanConfig, ScanResult, ScanType
from ports.scanner_port import ScannerPort


class FlutterOpenGrepScanner(ScannerPort):
    """Run Dart and embedded native rules only against their intended source trees."""

    REPORT_PATH = "opengrep_results.json"
    FLUTTER_SOURCE_DIRECTORIES = ("lib", "bin")

    def __init__(
        self,
        flutter_rules_path: Path,
        *,
        android_rules_path: Path | None = None,
        ios_rules_path: Path | None = None,
    ) -> None:
        self._flutter_rules_path = flutter_rules_path.resolve()
        self._android_rules_path = self._resolve_platform_rules_path("android", android_rules_path)
        self._ios_rules_path = self._resolve_platform_rules_path("ios", ios_rules_path)

    @property
    def scan_type(self) -> ScanType:
        return ScanType.OPENGREP_SOURCE

    @property
    def name(self) -> str:
        return "Flutter Scoped OpenGrep Scanner"

    @property
    def description(self) -> str:
        return "Scoped Flutter, Android, and iOS source-code security analysis with OpenGrep."

    def is_available(self) -> bool:
        return OpenGrepScanner().is_available()

    def scan(self, config: ScanConfig) -> list[ScanResult]:
        project_path = config.project_path.resolve()
        scope_specs = {
            "flutter": {
                "required": True,
                "rules_path": self._flutter_rules_path,
                "scan_paths": self._flutter_scan_paths(project_path),
            },
            "android": {
                "required": False,
                "rules_path": self._android_rules_path,
                "scan_paths": self._platform_scan_paths(project_path, "android"),
            },
            "ios": {
                "required": False,
                "rules_path": self._ios_rules_path,
                "scan_paths": self._platform_scan_paths(project_path, "ios"),
            },
        }

        scopes: dict[str, dict[str, Any]] = {}
        findings: list[dict[str, Any]] = []
        errors: list[dict[str, Any]] = []
        configured_rule_ids: set[str] = set()
        tool_versions: set[str] = set()

        for scope, spec in scope_specs.items():
            scope_metadata, scope_findings, scope_errors, tool_version = self._scan_scope(
                config,
                scope=scope,
                required=bool(spec["required"]),
                rules_path=spec["rules_path"],
                scan_paths=spec["scan_paths"],
            )
            scopes[scope] = scope_metadata
            findings.extend(scope_findings)
            errors.extend(scope_errors)
            if scope_metadata["status"] == "success":
                configured_rule_ids.update(scope_metadata["configured_rule_ids"])
            if tool_version:
                tool_versions.add(tool_version)

        status = self._aggregate_status(scopes)
        success = status != "failed"
        error_message = "No required Flutter OpenGrep scope completed successfully." if not success else ""
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
                "project_path": str(project_path),
                "configured_rule_ids": sorted(configured_rule_ids),
                "scopes": scopes,
            },
        }
        return [
            ScanResult(
                scanner_name=self.name,
                scan_type=self.scan_type,
                success=success,
                error_message=error_message,
                raw_output=json.dumps(payload, indent=2, sort_keys=True),
                relative_target_path=self.REPORT_PATH,
                description=self.description,
            )
        ]

    def _scan_scope(
        self,
        config: ScanConfig,
        *,
        scope: str,
        required: bool,
        rules_path: object,
        scan_paths: object,
    ) -> tuple[dict[str, Any], list[dict[str, Any]], list[dict[str, Any]], str]:
        rules_path = rules_path if isinstance(rules_path, Path) else None
        scan_paths = [path for path in scan_paths if isinstance(path, Path)] if isinstance(scan_paths, list) else []
        base_metadata: dict[str, Any] = {
            "status": "skipped",
            "required": required,
            "applicable": bool(scan_paths),
            "rules_path": str(rules_path) if rules_path else "",
            "scan_paths": [str(path) for path in scan_paths],
            "configured_rule_ids": [],
        }
        if not scan_paths:
            base_metadata["reason"] = (
                "No production Dart source paths were found."
                if scope == "flutter"
                else f"{scope.capitalize()} platform directory is not present."
            )
            return base_metadata, [], [], ""
        if rules_path is None or not rules_path.is_dir():
            base_metadata["reason"] = f"No {scope} OpenGrep rules directory was found."
            return base_metadata, [], [], ""

        result = OpenGrepScanner(rules_path=rules_path, scan_paths=scan_paths).scan(config)[0]
        try:
            payload = json.loads(result.raw_output)
        except json.JSONDecodeError:
            payload = {}
        report = payload if isinstance(payload, dict) else {}
        report_metadata = report.get("scan_metadata")
        report_metadata = report_metadata if isinstance(report_metadata, dict) else {}
        tool_version = str(report_metadata.get("tool_version", "")).strip()

        if not result.success:
            error = result.error_message or str(report.get("error", "")).strip() or "OpenGrep scope failed."
            base_metadata.update({"status": "failed", "reason": error})
            return base_metadata, [], [{"scope": scope, "error": error}], tool_version

        rule_ids = report_metadata.get("configured_rule_ids")
        configured = sorted(
            {str(rule_id).strip() for rule_id in rule_ids if str(rule_id).strip()}
            if isinstance(rule_ids, list)
            else set()
        )
        base_metadata.update({"status": "success", "configured_rule_ids": configured})
        findings = [
            {**finding, "phoenix_scope": scope} for finding in report.get("results", []) if isinstance(finding, dict)
        ]
        errors = [{**error, "scope": scope} for error in report.get("errors", []) if isinstance(error, dict)]
        return base_metadata, findings, errors, tool_version

    @staticmethod
    def _aggregate_status(scopes: dict[str, dict[str, Any]]) -> str:
        required_scope = scopes["flutter"]
        successful = [scope for scope in scopes.values() if scope["status"] == "success"]
        failed = [scope for scope in scopes.values() if scope["status"] == "failed"]
        if required_scope["status"] != "success":
            return "partial" if successful else "failed"
        incomplete_applicable = [
            scope for scope in scopes.values() if scope["applicable"] and scope["status"] != "success"
        ]
        return "partial" if failed or incomplete_applicable else "complete"

    def _resolve_platform_rules_path(self, scope: str, explicit_path: Path | None) -> Path | None:
        if explicit_path is not None:
            return explicit_path.resolve()
        candidates = [
            self._flutter_rules_path.parent / scope,
            Path(__file__).resolve().parents[3] / "rules" / scope,
            Path("/app/rules") / scope,
        ]
        return next((path.resolve() for path in candidates if path.is_dir()), None)

    @classmethod
    def _flutter_scan_paths(cls, project_path: Path) -> list[Path]:
        paths = [
            project_path / directory
            for directory in cls.FLUTTER_SOURCE_DIRECTORIES
            if (project_path / directory).is_dir()
        ]
        paths.extend(path for path in sorted(project_path.glob("*.dart")) if path.is_file())
        return paths

    @staticmethod
    def _platform_scan_paths(project_path: Path, platform: str) -> list[Path]:
        path = project_path / platform
        return [path] if path.is_dir() else []
