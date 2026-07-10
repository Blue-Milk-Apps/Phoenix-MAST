"""Artifact storage port."""

from __future__ import annotations

from pathlib import Path
from typing import Protocol

from domain.models import ScanConfig, ScanResult


class ArtifactStorePort(Protocol):
    """Port for durable storage of scanner artifacts."""

    def create_work_dir(self, prefix: str) -> Path: ...

    def persist(self, result: ScanResult, storage_path: Path) -> Path: ...

    def persist_scan_metadata(
        self,
        config: ScanConfig,
        storage_path: Path,
    ) -> Path: ...
