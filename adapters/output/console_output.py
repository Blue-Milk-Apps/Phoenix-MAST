"""Console scan output adapter."""

from __future__ import annotations

from domain.models import ScanResult
from ports.scan_output_port import ScanOutputPort


class ConsoleScanOutput(ScanOutputPort):
    """Write scan output to stdout."""

    def write_result(self, result: ScanResult) -> None:
        if result.skipped:
            status = "Skipped"
            detail = result.error_message
        elif result.success:
            status = "OK"
            detail = result.raw_output
        else:
            status = "Failed"
            detail = result.error_message or result.raw_output

        print(f"{result.scanner_name}: {status}")
        if detail:
            print(f"  {detail}")
