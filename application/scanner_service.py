"""Scanner service - orchestrates security scanning operations."""

import time

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

    def scan_project(self, config: ScanConfig, output: ScanOutputPort | None = None) -> list[ScanResult]:
        """Execute all enabled scanners and return aggregated report.

        Args:
            config: Scan configuration with paths and options.
            output: Destination for each scanner's results as soon as it finishes.

        Returns:
            List[ScanResult] with results from all scanners.
        """
        results: list[ScanResult] = []
        for scanner in self.scanners:
            print(f"Running {scanner.name}...")

            start = time.perf_counter()
            try:
                if not scanner.is_available():
                    raise RuntimeError("Required scanner is not available on this system.")
                scan_results = scanner.scan(config)
            except Exception as exc:
                raise RuntimeError(f"{scanner.name} failed: {exc}") from exc
            duration = time.perf_counter() - start
            for result in scan_results:
                result.duration_seconds = duration
                if output is not None:
                    output.write_result(result)
            if not scan_results:
                raise RuntimeError(f"{scanner.name} returned no execution results.")
            for result in scan_results:
                if not result.success or result.skipped:
                    raise RuntimeError(f"{scanner.name} failed: {result.error_message or 'Execution was incomplete.'}")
            results.extend(scan_results)

        return results
