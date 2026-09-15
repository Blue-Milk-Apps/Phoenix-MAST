"""OpenGrep scanner adapter for source-code security evidence extraction."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

from domain.models import ScanConfig, ScanResult, ScanType
from ports.scanner_port import ScannerPort

REPORT_PATH = "opengrep_results.json"


class OpenGrepScanner(ScannerPort):
    """Scanner for extracting source-code findings with OpenGrep."""

    DEFAULT_PROCESS_TIMEOUT_SECONDS = 300

    def __init__(self, rules_path: Path | None = None, scan_paths: list[Path] | None = None) -> None:
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
            completed = subprocess.run(
                [executable, "--version"],
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=10,
                check=False,
            )
        except Exception:
            self._tool_version = ""
            return ""

        version_output = completed.stdout.strip() or completed.stderr.strip()
        self._tool_version = version_output.splitlines()[0] if version_output else ""
        return self._tool_version

    def _get_rules_path(self, config: ScanConfig) -> Path | None:
        if self._rules_path:
            return self._rules_path if self._rules_path.exists() else None

        if config.opengrep_rules_path:
            return config.opengrep_rules_path if config.opengrep_rules_path.exists() else None
        return None

    def _has_rule_files(self, rules_path: Path) -> bool:
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
        return env

    def _get_scan_paths(self, config: ScanConfig) -> list[Path]:
        if self._scan_paths:
            return self._scan_paths
        return [config.project_path]

    def scan(self, config: ScanConfig) -> list[ScanResult]:
        opengrep_home = Path(tempfile.mkdtemp(prefix="phoenix_opengrep_"))
        process: subprocess.Popen[str] | None = None

        try:
            rules_path = self._get_rules_path(config)
            if not rules_path:
                return [self._failure("No rules path found. Please configure rules_path in config.")]
            if not self._has_rule_files(rules_path):
                return [self._failure(f"No OpenGrep rule files found in: {rules_path}")]

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
            cmd = [
                executable,
                "scan",
                "--config",
                str(rules_path),
                *(str(path) for path in scan_paths),
                "--json",
                "--no-rewrite-rule-ids",
                "--no-git-ignore",
                "--disable-version-check",
            ]

            if config.ignore_file and config.ignore_file.exists():
                cmd.extend(["--exclude-rules", str(config.ignore_file)])
            for pattern in config.ignore_patterns:
                cmd.extend(["--exclude", pattern])

            process = subprocess.Popen(
                cmd,
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

            if process.returncode not in (0, 1):
                return [self._failure(f"OpenGrep error with return code {process.returncode}", stdout_data)]

            return [
                ScanResult(
                    scanner_name=self.name,
                    scan_type=self.scan_type,
                    success=True,
                    raw_output=self._report(stdout_data, rules_path, scan_paths),
                    relative_target_path=REPORT_PATH,
                    description=self.description,
                )
            ]
        except subprocess.TimeoutExpired:
            if process is not None:
                process.kill()
                stdout_data, _stderr_data = process.communicate()
            else:
                stdout_data = ""
            return [self._failure(f"OpenGrep timed out after {self._timeout_seconds()} seconds", stdout_data)]
        except Exception as exc:
            return [self._failure(str(exc))]
        finally:
            shutil.rmtree(opengrep_home, ignore_errors=True)

    def _failure(self, error_message: str, raw_output: str = "") -> ScanResult:
        return ScanResult(
            scanner_name=self.name,
            scan_type=self.scan_type,
            success=False,
            error_message=error_message,
            raw_output=self._error_report(error_message, raw_output),
            relative_target_path=REPORT_PATH,
        )

    def _error_report(self, error_message: str, raw_output: str = "") -> str:
        report: dict[str, object] = {
            "error": error_message,
            "success": False,
        }
        if raw_output.strip():
            try:
                report["raw_output"] = json.loads(raw_output)
            except json.JSONDecodeError:
                report["raw_output"] = raw_output
        return json.dumps(report, indent=2, sort_keys=True)

    def _report(self, raw_output: str, rules_path: Path, scan_paths: list[Path]) -> str:
        if raw_output.strip():
            try:
                payload = json.loads(raw_output)
            except json.JSONDecodeError:
                payload = {"raw_output": raw_output}
        else:
            payload = {"results": []}

        if isinstance(payload, dict):
            payload.setdefault("results", [])
            payload.setdefault("errors", [])
            payload.setdefault("success", True)
            payload["scan_metadata"] = {
                "tool": "opengrep",
                "tool_version": self._opengrep_version(),
                "scanner_name": self.name,
                "scan_type": self.scan_type.value,
                "project_path": str(scan_paths[0]),
                "scan_paths": [str(path) for path in scan_paths],
                "rules_path": str(rules_path),
            }

        return json.dumps(payload, indent=2, sort_keys=True)
