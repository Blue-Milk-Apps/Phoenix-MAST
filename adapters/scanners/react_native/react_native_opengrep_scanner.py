"""Scoped OpenGrep orchestration for React Native source projects."""

from __future__ import annotations

import json
import os
from dataclasses import replace
from pathlib import Path
from typing import Any

from adapters.scanners.common import OpenGrepScanner
from domain.models import ScanConfig, ScanResult, ScanType
from ports.scanner_port import ScannerPort


class ReactNativeOpenGrepScanner(ScannerPort):
    """Run React Native and embedded native rules against isolated mobile scopes."""

    REPORT_PATH = "opengrep_results.json"
    MOBILE_SOURCE_SUFFIXES = frozenset({".js", ".jsx", ".ts", ".tsx"})
    EXCLUDED_DIRECTORY_NAMES = frozenset(
        {
            ".expo",
            ".next",
            "__fixtures__",
            "__mocks__",
            "__tests__",
            "build",
            "coverage",
            "dist",
            "e2e",
            "fixtures",
            "node_modules",
            "public",
            "stories",
            "test",
            "tests",
            "vendor",
            "web",
        }
    )
    REACT_NATIVE_EXCLUDE_PATTERNS = (
        "android/**",
        "**/android/**",
        "ios/**",
        "**/ios/**",
        "web/**",
        "**/web/**",
        "public/**",
        "**/public/**",
        "node_modules/**",
        "**/node_modules/**",
        ".expo/**",
        "**/.expo/**",
        ".next/**",
        "**/.next/**",
        "build/**",
        "**/build/**",
        "dist/**",
        "**/dist/**",
        "coverage/**",
        "**/coverage/**",
        "vendor/**",
        "**/vendor/**",
        "**/__tests__/**",
        "**/__fixtures__/**",
        "**/__mocks__/**",
        "**/test/**",
        "**/tests/**",
        "**/e2e/**",
        "**/stories/**",
        "**/*.web.js",
        "**/*.web.jsx",
        "**/*.web.ts",
        "**/*.web.tsx",
        "**/*.test.js",
        "**/*.test.jsx",
        "**/*.test.ts",
        "**/*.test.tsx",
        "**/*.spec.js",
        "**/*.spec.jsx",
        "**/*.spec.ts",
        "**/*.spec.tsx",
        "**/*.stories.js",
        "**/*.stories.jsx",
        "**/*.stories.ts",
        "**/*.stories.tsx",
    )

    def __init__(
        self,
        react_native_rules_path: Path,
        *,
        android_rules_path: Path | None = None,
        ios_rules_path: Path | None = None,
    ) -> None:
        self._react_native_rules_path = react_native_rules_path.resolve()
        self._android_rules_path = self._resolve_platform_rules_path("android", android_rules_path)
        self._ios_rules_path = self._resolve_platform_rules_path("ios", ios_rules_path)

    @property
    def scan_type(self) -> ScanType:
        return ScanType.OPENGREP_SOURCE

    @property
    def name(self) -> str:
        return "React Native Scoped OpenGrep Scanner"

    @property
    def description(self) -> str:
        return "Scoped React Native, Android, and iOS mobile source-code security analysis with OpenGrep."

    def is_available(self) -> bool:
        return OpenGrepScanner().is_available()

    def scan(self, config: ScanConfig) -> list[ScanResult]:
        project_path = config.project_path.resolve()
        scope_specs = {
            "react_native": {
                "required": True,
                "applicable": bool(self._mobile_source_files(project_path)),
                "rules_path": self._react_native_rules_path,
                "scan_paths": [project_path],
                "exclude_patterns": self.REACT_NATIVE_EXCLUDE_PATTERNS,
            },
            "android": {
                "required": False,
                "applicable": (project_path / "android").is_dir(),
                "rules_path": self._android_rules_path,
                "scan_paths": self._platform_scan_paths(project_path, "android"),
                "exclude_patterns": (),
            },
            "ios": {
                "required": False,
                "applicable": (project_path / "ios").is_dir(),
                "rules_path": self._ios_rules_path,
                "scan_paths": self._platform_scan_paths(project_path, "ios"),
                "exclude_patterns": (),
            },
        }

        scopes: dict[str, dict[str, Any]] = {}
        findings: list[dict[str, Any]] = []
        errors: list[dict[str, Any]] = []
        configured_rule_ids: set[str] = set()
        tool_versions: set[str] = set()

        for scope, spec in scope_specs.items():
            metadata, scope_findings, scope_errors, tool_version = self._scan_scope(
                config,
                scope=scope,
                required=bool(spec["required"]),
                applicable=bool(spec["applicable"]),
                rules_path=spec["rules_path"],
                scan_paths=spec["scan_paths"],
                exclude_patterns=spec["exclude_patterns"],
            )
            scopes[scope] = metadata
            findings.extend(scope_findings)
            errors.extend(scope_errors)
            if metadata["status"] == "success":
                configured_rule_ids.update(metadata["configured_rule_ids"])
            if tool_version:
                tool_versions.add(tool_version)

        status = self._aggregate_status(scopes)
        success = status != "failed"
        error_message = "No required React Native OpenGrep scope completed successfully." if not success else ""
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
        applicable: bool,
        rules_path: object,
        scan_paths: object,
        exclude_patterns: object,
    ) -> tuple[dict[str, Any], list[dict[str, Any]], list[dict[str, Any]], str]:
        rules_path = rules_path if isinstance(rules_path, Path) else None
        scan_paths = [path for path in scan_paths if isinstance(path, Path)] if isinstance(scan_paths, list) else []
        exclusions = (
            [pattern for pattern in exclude_patterns if isinstance(pattern, str)]
            if isinstance(exclude_patterns, tuple)
            else []
        )
        metadata: dict[str, Any] = {
            "status": "skipped",
            "required": required,
            "applicable": applicable,
            "rules_path": str(rules_path) if rules_path else "",
            "scan_paths": [str(path) for path in scan_paths],
            "configured_rule_ids": [],
        }
        if not applicable or not scan_paths:
            metadata["reason"] = (
                "No eligible mobile JavaScript or TypeScript source files were found."
                if scope == "react_native"
                else f"{scope.capitalize()} platform directory is not present."
            )
            return metadata, [], [], ""
        if rules_path is None or not rules_path.is_dir():
            metadata["reason"] = f"No {scope.replace('_', ' ')} OpenGrep rules directory was found."
            return metadata, [], [], ""

        scope_config = replace(
            config,
            ignore_patterns=list(dict.fromkeys([*config.ignore_patterns, *exclusions])),
        )
        result = OpenGrepScanner(rules_path=rules_path, scan_paths=scan_paths).scan(scope_config)[0]
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
            metadata.update({"status": "failed", "reason": error})
            return metadata, [], [{"scope": scope, "error": error}], tool_version

        rule_ids = report_metadata.get("configured_rule_ids")
        configured = sorted(
            {str(rule_id).strip() for rule_id in rule_ids if str(rule_id).strip()}
            if isinstance(rule_ids, list)
            else set()
        )
        metadata.update({"status": "success", "configured_rule_ids": configured})
        findings = [
            {**finding, "phoenix_scope": scope} for finding in report.get("results", []) if isinstance(finding, dict)
        ]
        errors = [{**error, "scope": scope} for error in report.get("errors", []) if isinstance(error, dict)]
        return metadata, findings, errors, tool_version

    @staticmethod
    def _aggregate_status(scopes: dict[str, dict[str, Any]]) -> str:
        required_scope = scopes["react_native"]
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
            self._react_native_rules_path.parent / scope,
            Path(__file__).resolve().parents[3] / "rules" / scope,
            Path("/app/rules") / scope,
        ]
        return next((path.resolve() for path in candidates if path.is_dir()), None)

    @classmethod
    def _mobile_source_files(cls, project_path: Path) -> list[Path]:
        if not project_path.is_dir():
            return []
        excluded_directories = cls.EXCLUDED_DIRECTORY_NAMES | {"android", "ios"}
        source_files: list[Path] = []
        for current_root, directory_names, file_names in os.walk(project_path):
            directory_names[:] = sorted(name for name in directory_names if name.lower() not in excluded_directories)
            root = Path(current_root)
            for file_name in sorted(file_names):
                path = root / file_name
                if path.suffix.lower() not in cls.MOBILE_SOURCE_SUFFIXES:
                    continue
                if cls._excluded_source_path(path, project_path):
                    continue
                source_files.append(path)
        return source_files

    @classmethod
    def _excluded_source_path(cls, path: Path, project_path: Path) -> bool:
        relative = path.relative_to(project_path)
        directory_names = {part.lower() for part in relative.parts[:-1]}
        if directory_names.intersection(cls.EXCLUDED_DIRECTORY_NAMES | {"android", "ios"}):
            return True
        name = path.name.lower()
        return any(marker in name for marker in (".web.", ".test.", ".spec.", ".stories."))

    @staticmethod
    def _platform_scan_paths(project_path: Path, platform: str) -> list[Path]:
        path = project_path / platform
        return [path] if path.is_dir() else []
