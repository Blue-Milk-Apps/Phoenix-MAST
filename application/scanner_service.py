"""Scanner service - orchestrates security scanning operations."""

import json
import time
from typing import List

from domain.models import ScanConfig, ScanResult
from ports.scanner_port import ScannerPort


class ScannerService:
    """Orchestrates multiple scanners and aggregates results."""

    def __init__(
        self,
        scanners: list[ScannerPort] | None = None,
    ) -> None:
        self.scanners = scanners or []

    def scan_project(self, config: ScanConfig) -> List[ScanResult]:
        """Execute all enabled scanners and return aggregated report.

        Args:
            config: Scan configuration with paths and options.

        Returns:
            List[ScanResult] with results from all scanners.
        """
        results: list[ScanResult] = []
        for scanner in self.scanners:
            print(f"Running {scanner.name}...")

            if not scanner.is_available():
                error_message = f"{scanner.name} is not available on this system."
                result = ScanResult(
                    scanner_name=scanner.name,
                    scan_type=scanner.scan_type,
                    success=False,
                    skipped=True,
                    error_message=error_message,
                    raw_output=json.dumps(
                        {
                            "error": error_message,
                            "skipped": True,
                            "success": False,
                        },
                        indent=2,
                        sort_keys=True,
                    ),
                    relative_target_path="scan_summary.json",
                )
                results.append(result)
                continue

            start = time.perf_counter()
            scan_results = scanner.scan(config)
            duration = time.perf_counter() - start
            for result in scan_results:
                result.duration_seconds = duration
            results.extend(scan_results)

        return results
