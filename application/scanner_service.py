"""Scanner service - orchestrates security scanning operations."""

import json
import time
from dataclasses import replace

from adapters.output.console_output import ConsoleScanOutput
from domain.models import ScanConfig, ScanResult
from ports.scan_output_port import ScanOutputPort
from ports.scanner_port import ScannerPort


class ScannerService:
    """Orchestrates multiple scanners and aggregates results."""

    def __init__(
        self,
        scanners: list[ScannerPort] | None = None,
    ) -> None:
        self.scanners = scanners or []
        self.console = ConsoleScanOutput()

    def scan_project(
        self, config: ScanConfig, output: ScanOutputPort | None = None, *, retain_output: bool = True
    ) -> list[ScanResult]:
        """Execute all enabled scanners and return aggregated report.

        Args:
            config: Scan configuration with paths and options.
            output: Destination for each scanner's results as soon as it finishes.

        Returns:
            List[ScanResult] with results from all scanners.
        """
        results: list[ScanResult] = []
        for scanner in self.scanners:
            self.console.tool_status(scanner.name, "START")

            start = time.perf_counter()
            try:
                if not scanner.is_available():
                    raise RuntimeError("Required scanner is not available on this system.")
                scan_results = scanner.scan(config)
            except Exception as exc:
                self.console.tool_status(scanner.name, "FAILED", f"{time.perf_counter() - start:.2f}s | {exc}")
                raise RuntimeError(f"{scanner.name} failed: {exc}") from exc
            duration = time.perf_counter() - start
            for result in scan_results:
                result.duration_seconds = duration
                if config.display_project_path and config.display_project_path != str(config.project_path):
                    old = str(config.project_path)
                    new = config.display_project_path
                    result.raw_output = result.raw_output.replace(json.dumps(old)[1:-1], json.dumps(new)[1:-1]).replace(
                        old, new
                    )
                    result.artifact_files = {
                        name: content.replace(json.dumps(old)[1:-1], json.dumps(new)[1:-1]).replace(old, new)
                        for name, content in result.artifact_files.items()
                    }
                if output is not None:
                    output.write_result(result)
            if not scan_results:
                self.console.tool_status(scanner.name, "FAILED", "No execution results returned")
                raise RuntimeError(f"{scanner.name} returned no execution results.")
            for result in scan_results:
                if not result.success or result.skipped:
                    self.console.tool_status(scanner.name, "FAILED", f"{duration:.2f}s | partial artifacts saved")
                    raise RuntimeError(f"{scanner.name} failed: {result.error_message or 'Execution was incomplete.'}")
            self.console.tool_status(scanner.name, "OK", f"{duration:.2f}s | {len(scan_results)} artifacts")
            results.extend(
                scan_results
                if retain_output or output is None
                else [replace(result, raw_output="", artifact_files={}) for result in scan_results]
            )

        return results
