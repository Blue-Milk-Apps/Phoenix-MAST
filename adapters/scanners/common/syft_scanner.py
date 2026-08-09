"""Platform-neutral Syft scanner adapter for SBOM generation."""

import json
import shutil
import subprocess

from domain.models import ScanConfig, ScanResult, ScanType
from ports.scanner_port import ScannerPort

REPORT_PATH = "sbom.json"


class SyftScanner(ScannerPort):
    """Scanner for generating Software Bill of Materials using Syft."""

    DEFAULT_OUTPUT_FORMAT = "syft-json"

    def __init__(self, output_format: str = DEFAULT_OUTPUT_FORMAT) -> None:
        self.output_format = output_format

    @property
    def scan_type(self) -> ScanType:
        return ScanType.SYFT

    @property
    def name(self) -> str:
        return "Syft SBOM Generator"

    @property
    def description(self) -> str:
        return (
            "A Software Bill of Materials (SBOM) listing all third-party packages and libraries "
            "detected in the project. This inventory helps track dependency versions and identify "
            "components that may require security updates."
        )

    def is_available(self) -> bool:
        return shutil.which("syft") is not None

    def scan(self, config: ScanConfig) -> list[ScanResult]:
        try:
            scan_target = (
                config.extracted_binary.scan_root_path if config.extracted_binary is not None else config.project_path
            )
            output_format = self._stdout_output_format()
            cmd = [
                "syft",
                "scan",
                str(scan_target),
                "-o",
                output_format,
            ]

            print(f"{ScannerPort.format_stdout_prefix(self.scan_type)}Scanning filesystem...")

            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )

            stdout_data, stderr_data = process.communicate()

            for line in stderr_data.splitlines():
                clean_line = line.replace("\r", "").strip()
                if not clean_line:
                    continue
                print(f"{ScannerPort.format_stdout_prefix(self.scan_type)}{clean_line}")

            if process.returncode != 0:
                error_message = f"Syft error: {process.returncode}"
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

            print(f"{ScannerPort.format_stdout_prefix(self.scan_type)}Scan complete.")

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

    def _stdout_output_format(self) -> str:
        output_format = self.output_format.strip()
        if not output_format:
            return self.DEFAULT_OUTPUT_FORMAT
        if "=" in output_format:
            raise ValueError(
                "Syft output format must not include a file path. "
                "Use a format such as 'syft-json', 'spdx-json', or 'syft-json'."
            )
        if not output_format.endswith("-json"):
            raise ValueError(
                "Syft output format must be JSON so phoenix can persist a .json report. "
                "Use a format such as 'syft-json', 'spdx-json', or 'syft-json'."
            )
        return output_format

    @staticmethod
    def _json_report(raw_output: str) -> str:
        if not raw_output.strip():
            return "{}"
        return json.dumps(json.loads(raw_output), sort_keys=True)

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
