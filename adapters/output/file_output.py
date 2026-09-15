"""File scan output adapter."""

from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path

from adapters.storage import StoreToFile
from domain.models import ScanConfig, ScanResult
from ports.scan_output_port import ScanOutputPort
from ports.storage_port import ArtifactStorePort


class FileScanOutput(ScanOutputPort):
    """Write scan output artifacts to a filesystem location."""

    def __init__(
        self,
        storage_path: Path | str,
        artifact_store: ArtifactStorePort | None = None,
    ) -> None:
        self._storage_path = Path(storage_path)
        self._artifact_store = artifact_store or StoreToFile(self._storage_path)

    def write_result(self, result: ScanResult) -> None:
        self._artifact_store.persist(result, self._storage_path)

    def write_scan_metadata(
        self,
        config: ScanConfig,
        report_context: Mapping[str, str],
    ) -> Path:
        return self._artifact_store.persist_scan_metadata(
            config,
            report_context,
            self._storage_path,
        )
