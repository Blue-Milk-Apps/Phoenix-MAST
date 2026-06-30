"""Trufflehog scanner adapter for secrets detection."""

import json
import shutil
import subprocess

from domain.models import ScanConfig, ScanResult, ScanType
from ports.scanner_port import ScannerPort

REPORT_PATH = "trufflehog_results.json"


class TrufflehogScanner(ScannerPort):
    """Scanner for detecting leaked secrets using Trufflehog."""

    @property
    def scan_type(self) -> ScanType:
        return ScanType.TRUFFLEHOG

    @property
    def name(self) -> str:
        return "Trufflehog Secrets Scanner"

    @property
    def description(self) -> str:
        return (
            "Verified secrets and credentials detected in the codebase. "
            "These results represent API keys, tokens, passwords, and other sensitive values "
            "that have been confirmed as active and should be revoked immediately."
        )

    def is_available(self) -> bool:
        return shutil.which("trufflehog") is not None

    def scan(self, config: ScanConfig) -> list[ScanResult]:
        cmd = [
            "trufflehog",
            "filesystem",
            str(config.project_path),
            "--log-level=-1",  # Any level above -1 is too verbose for our purposes
            "--json",
            "--no-update",
            "--only-verified",  # Only shows things that matter
        ]

        try:
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,  # JSON output (newline-delimited)
                stderr=subprocess.PIPE,  # Status messages
                text=True,
            )

            stdout_data, stderr_data = process.communicate()

            for line in stderr_data.splitlines():
                clean_line = line.replace("\r", "").strip()
                if not clean_line:
                    continue
                print(f"{ScannerPort.format_stdout_prefix(self.scan_type)}{clean_line}")

            if process.returncode not in (0, 1):
                error_message = f"Trufflehog error with code {process.returncode}"
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
                    raw_output=self._json_report(stdout_data),
                    relative_target_path=REPORT_PATH,
                    description=self.description,
                )
            ]
        except Exception as e:
            return [
                ScanResult(
                    scanner_name=self.name,
                    scan_type=self.scan_type,
                    success=False,
                    error_message=str(e),
                    raw_output=self._error_report(str(e)),
                    relative_target_path=REPORT_PATH,
                )
            ]

    @staticmethod
    def _json_report(raw_output: str) -> str:
        items = []
        for line in raw_output.splitlines():
            if line.strip():
                items.append(json.loads(line))
        return json.dumps(items, indent=2, sort_keys=True)

    def _error_report(self, error_message: str, raw_output: str = "") -> str:
        report: dict[str, object] = {
            "error": error_message,
            "success": False,
        }
        if raw_output.strip():
            try:
                report["raw_output"] = json.loads(self._json_report(raw_output))
            except json.JSONDecodeError:
                report["raw_output"] = raw_output
        return json.dumps(report, indent=2, sort_keys=True)
