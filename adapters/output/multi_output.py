"""Composite scan output adapter."""

from __future__ import annotations

from domain.models import ScanResult
from ports.scan_output_port import ScanOutputPort


class MultiScanOutput(ScanOutputPort):
    """Write scan output to multiple destinations."""

    def __init__(self, outputs: list[ScanOutputPort]) -> None:
        self._outputs = outputs

    def write_result(self, result: ScanResult) -> None:
        for output in self._outputs:
            output.write_result(result)
