"""Platform-neutral OpenGrep scanner adapter for security evidence extraction."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

import yaml

from domain.models import ScanConfig, ScanResult, ScanType
from ports.scanner_port import ScannerPort

REPORT_PATH = "opengrep_results.json"


class OpenGrepScanner(ScannerPort):
    """Scanner for extracting source-code findings with OpenGrep."""

    DEFAULT_PROCESS_TIMEOUT_SECONDS = 300

    def __init__(
        self,
        rules_path: Path | None = None,
        scan_paths: list[Path] | None = None,
        *,
        rules_paths: list[Path] | None = None,
    ) -> None:
        if rules_path is not None and rules_paths is not None:
            raise ValueError("Pass rules_path or rules_paths, not both.")
        self._rules_paths = list(dict.fromkeys(path.resolve() for path in rules_paths)) if rules_paths else []
        self._rules_path = rules_path.resolve() if rules_path else None
        self._scan_paths = [path.resolve() for path in scan_paths] if scan_paths else None
        self._tool_version: str | None = None

    @property
    def scan_type(self) -> ScanType:
        return ScanType.OPENGREP_SOURCE

    @property
    def name(self) -> str:
        return "OpenGrep NIAP/MASVS Scanner"

    @property
    def description(self) -> str:
        return (
            "Static analysis and security evidence extraction based on NIAP, OWASP MASVS, and Phoenix OpenGrep rules."
        )

    def _opengrep_executable(self) -> str | None:
        found = shutil.which("opengrep")
        if found:
            return found
        venv_opengrep = Path(sys.executable).parent / "opengrep"
        if venv_opengrep.is_file():
            return str(venv_opengrep)
        return None

    def _opengrep_core_executable(self) -> str | None:
        found = shutil.which("opengrep-core")
        if found:
            return found
        venv_opengrep_core = Path(sys.executable).parent / "opengrep-core"
        if venv_opengrep_core.is_file():
            return str(venv_opengrep_core)
        return None

    def is_available(self) -> bool:
        return self._opengrep_executable() is not None and self._opengrep_core_executable() is not None

    def _opengrep_version(self) -> str:
        if self._tool_version is not None:
            return self._tool_version

        executable = self._opengrep_executable()
        if not executable:
            self._tool_version = ""
            return ""

        try:
            with tempfile.TemporaryDirectory(prefix="phoenix_opengrep_version_") as directory:
                completed = subprocess.run(
                    [executable, "--version"],
                    text=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    timeout=10,
                    check=False,
                    env=self._opengrep_env(Path(directory)),
                )
        except Exception:
            self._tool_version = ""
            return ""

        version_output = completed.stdout.strip() if completed.returncode == 0 else ""
        self._tool_version = version_output.splitlines()[0] if version_output else ""
        return self._tool_version

    def _get_rules_path(self, config: ScanConfig) -> Path | None:
        if self._rules_path:
            return self._rules_path if self._rules_path.exists() else None

        if config.opengrep_rules_path:
            return config.opengrep_rules_path if config.opengrep_rules_path.exists() else None
        return None

    def _has_rule_files(self, rules_path: Path) -> bool:
        if rules_path.is_file():
            return rules_path.suffix.lower() in {".yml", ".yaml"}
        return any(path.is_file() and path.suffix.lower() in {".yml", ".yaml"} for path in rules_path.rglob("*"))

    def _timeout_seconds(self) -> int:
        raw = (
            os.environ.get("PHOENIX_OPENGREP_TIMEOUT", "").strip()
            or os.environ.get("PHOENIX_OPENGREP_TIMEOUT", "").strip()
        )
        if not raw:
            return self.DEFAULT_PROCESS_TIMEOUT_SECONDS
        try:
            return max(1, int(raw))
        except ValueError:
            return self.DEFAULT_PROCESS_TIMEOUT_SECONDS

    def _opengrep_env(self, opengrep_home: Path) -> dict[str, str]:
        opengrep_home.mkdir(parents=True, exist_ok=True)
        env = os.environ.copy()
        env.setdefault("OPENGREP_OFFLINE", "1")
        env.setdefault("OPENGREP_DISABLE_METRICS", "1")
        env.setdefault("OPENGREP_SEND_METRICS", "off")
        env.setdefault("SEMGREP_SEND_METRICS", "off")
        env.setdefault("SEMGREP_LOG_FILE", str(opengrep_home / "opengrep.log"))
        env.setdefault("SEMGREP_SETTINGS_FILE", str(opengrep_home / "settings.yml"))
        return env

    def _get_scan_paths(self, config: ScanConfig) -> list[Path]:
        if self._scan_paths:
            return self._scan_paths
        return [config.project_path]

    def scan(self, config: ScanConfig) -> list[ScanResult]:
        opengrep_home = Path(tempfile.mkdtemp(prefix="phoenix_opengrep_"))
        process: subprocess.Popen[str] | None = None
        command: list[str] | None = None

        try:
            rules_path = self._rules_paths or self._get_rules_path(config)
            if not rules_path:
                return [self._failure("No rules path found. Please configure rules_path in config.")]
            rule_paths = rules_path if isinstance(rules_path, list) else [rules_path]
            for path in rule_paths:
                mode_directory = path if path.is_dir() else path.parent
                if mode_directory.name in {"source", "binary"} and mode_directory.name != config.mode.lower():
                    return [self._failure("The selected rules directory conflicts with the execution mode.")]
                if not self._has_rule_files(path):
                    return [self._failure(f"No OpenGrep rule files found in: {path}")]
            self._configured_rule_ids(rules_path)

            executable = self._opengrep_executable()
            if not executable:
                return [self._failure("OpenGrep executable was not found on this system.")]
            if not self._opengrep_core_executable():
                return [
                    self._failure(
                        "OpenGrep core executable was not found on this system. "
                        "Install a real opengrep-core binary or use the Docker image."
                    )
                ]

            scan_paths = self._get_scan_paths(config)
            command = [
                executable,
                "scan",
                *(argument for path in rule_paths for argument in ("--config", str(path))),
                *(str(path) for path in scan_paths),
                "--json",
                "--strict",
                "--no-rewrite-rule-ids",
                "--no-git-ignore",
                "--disable-version-check",
            ]

            if config.ignore_file and config.ignore_file.exists():
                command.extend(["--exclude-rules", str(config.ignore_file)])
            for pattern in config.ignore_patterns:
                command.extend(["--exclude", pattern])

            process = subprocess.Popen(
                command,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=self._opengrep_env(opengrep_home),
            )
            stdout_data, stderr_data = process.communicate(timeout=self._timeout_seconds())

            for line in stderr_data.splitlines():
                clean_line = line.replace("\r", "").rstrip()
                if clean_line:
                    print(f"{ScannerPort.format_stdout_prefix(self.scan_type)}{clean_line}")

            if process.returncode != 0:
                return [
                    self._failure(
                        f"OpenGrep error with return code {process.returncode}",
                        stdout_data,
                        stderr_output=stderr_data,
                        command=command,
                        return_code=process.returncode,
                    )
                ]

            report = self._report(stdout_data, rules_path, scan_paths)
            payload = json.loads(report)
            valid_output = isinstance(payload, dict) and payload.get("success") is not False
            errors = payload.get("errors", []) if isinstance(payload, dict) else []
            return [
                ScanResult(
                    scanner_name=self.name,
                    scan_type=self.scan_type,
                    success=valid_output,
                    error_message=""
                    if valid_output
                    else f"OpenGrep returned invalid or incomplete output: {json.dumps(errors)}",
                    raw_output=report,
                    relative_target_path=REPORT_PATH,
                    description=self.description,
                )
            ]
        except subprocess.TimeoutExpired:
            if process is not None:
                process.kill()
                stdout_data, stderr_data = process.communicate()
            else:
                stdout_data = ""
                stderr_data = ""
            return [
                self._failure(
                    f"OpenGrep timed out after {self._timeout_seconds()} seconds",
                    stdout_data,
                    stderr_output=stderr_data,
                    command=command,
                )
            ]
        except Exception as exc:
            return [self._failure(str(exc), command=command)]
        finally:
            shutil.rmtree(opengrep_home, ignore_errors=True)

    def _failure(
        self,
        error_message: str,
        raw_output: str = "",
        *,
        stderr_output: str = "",
        command: list[str] | None = None,
        return_code: int | None = None,
    ) -> ScanResult:
        if stderr_output.strip():
            error_message = f"{error_message}: {stderr_output.strip()}"
        return ScanResult(
            scanner_name=self.name,
            scan_type=self.scan_type,
            success=False,
            error_message=error_message,
            raw_output=self._error_report(
                error_message,
                raw_output,
                stderr_output=stderr_output,
                command=command,
                return_code=return_code,
            ),
            relative_target_path=REPORT_PATH,
        )

    def _error_report(
        self,
        error_message: str,
        raw_output: str = "",
        *,
        stderr_output: str = "",
        command: list[str] | None = None,
        return_code: int | None = None,
    ) -> str:
        report: dict[str, object] = {
            "error": error_message,
            "success": False,
        }
        if return_code is not None:
            report["return_code"] = return_code
        if command:
            report["command"] = command
        if stderr_output.strip():
            report["stderr"] = stderr_output
        if raw_output.strip():
            try:
                report["raw_output"] = json.loads(raw_output)
            except json.JSONDecodeError:
                report["raw_output"] = raw_output
        return json.dumps(report, indent=2, sort_keys=True)

    def _report(self, raw_output: str, rules_path: Path | list[Path], scan_paths: list[Path]) -> str:
        if raw_output.strip():
            try:
                payload = json.loads(raw_output)
            except json.JSONDecodeError:
                payload = {
                    "raw_output": raw_output,
                    "success": False,
                    "errors": [{"message": "Invalid OpenGrep JSON output."}],
                }
        else:
            payload = {"success": False, "errors": [{"message": "Empty OpenGrep output."}]}

        if isinstance(payload, dict):
            if not isinstance(payload.get("results"), list):
                payload["success"] = False
                payload.setdefault("errors", []).append({"message": "OpenGrep did not return a findings list."})
            payload.setdefault("results", [])
            payload.setdefault("errors", [])
            payload.setdefault("success", True)
            if isinstance(payload.get("paths"), dict) and payload["paths"].get("scanned") == []:
                payload["errors"].append({"message": "No eligible files were scanned."})
            if payload["errors"]:
                payload["success"] = False
            payload["scan_metadata"] = {
                "tool": "opengrep",
                "tool_version": self._opengrep_version(),
                "scanner_name": self.name,
                "scan_type": self.scan_type.value,
                "project_path": str(scan_paths[0]),
                "scan_paths": [str(path) for path in scan_paths],
                "rules_path": str(rules_path) if isinstance(rules_path, Path) else "",
                "rules_paths": [str(path) for path in rules_path]
                if isinstance(rules_path, list)
                else [str(rules_path)],
                "configured_rule_ids": self._configured_rule_ids(rules_path),
            }

        return json.dumps(payload, indent=2, sort_keys=True)

    @staticmethod
    def _configured_rule_ids(rules_path: Path | list[Path]) -> list[str]:
        rule_ids: set[str] = set()
        roots = rules_path if isinstance(rules_path, list) else [rules_path]
        paths = set()
        for root in roots:
            paths.update([root] if root.is_file() else root.rglob("*"))
        for path in sorted(paths):
            if not path.is_file() or path.suffix.lower() not in {".yml", ".yaml"}:
                continue
            document = yaml.safe_load(path.read_text(encoding="utf-8"))
            if not isinstance(document, dict) or not isinstance(document.get("rules"), list):
                raise ValueError(f"Invalid rule configuration: {path}")
            for rule in document["rules"]:
                rule_id = rule.get("id") if isinstance(rule, dict) else None
                if not isinstance(rule_id, str) or not rule_id.strip():
                    raise ValueError(f"Rule with missing id in {path}")
                if rule_id in rule_ids:
                    raise ValueError(f"Duplicate rule id across selected configurations: {rule_id}")
                rule_ids.add(rule_id)
        return sorted(rule_ids)
