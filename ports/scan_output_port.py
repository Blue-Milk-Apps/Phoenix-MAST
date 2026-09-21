"""Scan output port."""

from __future__ import annotations

from typing import Protocol

from domain.models import ScanResult


class ScanOutputPort(Protocol):
    """Port for sending scan output to a user-facing destination."""

    def write_result(self, result: ScanResult) -> None: ...
