"""Gitleaks scanner adapter for secret detection."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

from domain.models import ScanConfig, ScanResult, ScanType
from ports.scanner_port import ScannerPort

REPORT_PATH = "gitleaks_report.json"


class GitleaksScanner(ScannerPort):
    """Scanner for detecting leaked secrets using Gitleaks."""

    DEFAULT_PROCESS_TIMEOUT_SECONDS = 300

    @property
    def scan_type(self) -> ScanType:
        return ScanType.GITLEAKS

    @property
    def name(self) -> str:
        return "Gitleaks Secrets Scanner"

    @property
    def description(self) -> str:
        return (
            "Detected secrets, API keys, tokens, passwords, and other sensitive values in "
            "the target project using Gitleaks rules."
        )

    def _gitleaks_executable(self) -> str | None:
        found = shutil.which("gitleaks")
        if found:
            return found

        venv_gitleaks = Path(sys.executable).parent / "gitleaks"
        if venv_gitleaks.is_file():
            return str(venv_gitleaks)

        return None

    def is_available(self) -> bool:
        return self._gitleaks_executable() is not None

    def _timeout_seconds(self) -> int:
        value = os.environ.get(
            "PHOENIX_GITLEAKS_TIMEOUT",
            str(self.DEFAULT_PROCESS_TIMEOUT_SECONDS),
        )
        try:
            return max(1, int(value))
        except ValueError:
            return self.DEFAULT_PROCESS_TIMEOUT_SECONDS

    def _resolve_config_path(self, config: ScanConfig) -> Path | None:
        env_config = os.environ.get("GITLEAKS_CONFIG", "").strip()
        if env_config:
            config_path = Path(env_config).expanduser()
            return config_path.resolve() if config_path.exists() else None

        project_config = config.project_path / ".gitleaks.toml"
        if project_config.is_file():
            return project_config.resolve()

        return None

    def scan(self, config: ScanConfig) -> list[ScanResult]:
        try:
            env_config = os.environ.get("GITLEAKS_CONFIG", "").strip()
            if env_config:
                env_config_path = Path(env_config).expanduser()
                if not env_config_path.exists():
                    error_message = (
                        f"GITLEAKS_CONFIG path does not exist: {env_config_path}"
                    )
                    return [
                        ScanResult(
                            scanner_name=self.name,
                            scan_type=self.scan_type,
                            success=False,
                            error_message=error_message,
                            raw_output=self._error_report(error_message),
                            relative_target_path=REPORT_PATH,
                        )
                    ]

            executable = self._gitleaks_executable()
            if not executable:
                error_message = "Gitleaks executable was not found on this system."
                return [
                    ScanResult(
                        scanner_name=self.name,
                        scan_type=self.scan_type,
                        success=False,
                        error_message=error_message,
                        raw_output=self._error_report(error_message),
                        relative_target_path=REPORT_PATH,
                    )
                ]

            cmd = [
                executable,
                "dir",
                "--no-banner",
                "--no-color",
                "--log-level",
                "fatal",
                "--report-format",
                "json",
                "--report-path",
                "-",
            ]

            config_path = self._resolve_config_path(config)
            if config_path:
                cmd.extend(["--config", str(config_path)])

            cmd.append(str(config.project_path))

            process = subprocess.Popen(
                cmd,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            stdout_data, stderr_data = process.communicate(
                timeout=self._timeout_seconds()
            )

            if stderr_data:
                for line in stderr_data.splitlines():
                    clean_line = line.replace("\r", "").strip()
                    if clean_line:
                        print(
                            f"{ScannerPort.format_stdout_prefix(self.scan_type)}{clean_line}"
                        )

            if process.returncode not in (0, 1):
                error_message = f"Gitleaks error with return code {process.returncode}"
                return [
                    ScanResult(
                        scanner_name=self.name,
                        scan_type=self.scan_type,
                        success=False,
                        error_message=error_message,
                        raw_output=self._error_report(error_message, stdout_data),
                        relative_target_path=REPORT_PATH,
                    )
                ]

            return [
                ScanResult(
                    scanner_name=self.name,
                    scan_type=self.scan_type,
                    success=True,
                    raw_output=self._json_report(stdout_data, []),
                    relative_target_path=REPORT_PATH,
                    description=self.description,
                )
            ]
        except subprocess.TimeoutExpired:
            process.kill()
            stdout_data, stderr_data = process.communicate()
            if stderr_data:
                for line in stderr_data.splitlines():
                    clean_line = line.replace("\r", "").strip()
                    if clean_line:
                        print(
                            f"{ScannerPort.format_stdout_prefix(self.scan_type)}{clean_line}"
                        )
            error_message = (
                f"Gitleaks timed out after {self._timeout_seconds()} seconds"
            )
            return [
                ScanResult(
                    scanner_name=self.name,
                    scan_type=self.scan_type,
                    success=False,
                    error_message=error_message,
                    raw_output=self._error_report(error_message, stdout_data),
                    relative_target_path=REPORT_PATH,
                )
            ]
        except Exception as exc:
            return [
                ScanResult(
                    scanner_name=self.name,
                    scan_type=self.scan_type,
                    success=False,
                    error_message=str(exc),
                    raw_output=self._error_report(str(exc)),
                    relative_target_path=REPORT_PATH,
                )
            ]

    @staticmethod
    def _json_report(raw_output: str, default: object) -> str:
        if not raw_output.strip():
            return json.dumps(default, indent=2, sort_keys=True)
        return json.dumps(json.loads(raw_output), indent=2, sort_keys=True)

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
