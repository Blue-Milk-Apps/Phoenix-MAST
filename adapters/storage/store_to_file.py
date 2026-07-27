"""File-system artifact storage adapter."""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

from domain.models import ScanConfig, ScanResult
from ports.storage_port import ArtifactStorePort

SCAN_METADATA_FILE_NAME = "scan_metadata.json"


class StoreToFile(ArtifactStorePort):
    """Store scan result artifacts on the local filesystem."""

    def __init__(self, storage_root: Path | str) -> None:
        self._storage_root = Path(storage_root)

    def create_work_dir(self, prefix: str) -> Path:
        work_root = self._storage_root / "work"
        work_root.mkdir(parents=True, exist_ok=True)
        return Path(tempfile.mkdtemp(prefix=f"{prefix}_", dir=work_root))

    def persist(self, result: ScanResult, storage_path: Path) -> Path:
        output_dir = Path(storage_path)
        output_dir.mkdir(parents=True, exist_ok=True)
        target = self._target_path(output_dir, result)
        target.parent.mkdir(parents=True, exist_ok=True)
        content = result.raw_output or result.error_message
        target.write_text(content, encoding="utf-8")
        for relative_path, artifact_content in result.artifact_files.items():
            artifact_target = self._artifact_target_path(
                output_dir,
                result,
                relative_path,
            )
            artifact_target.parent.mkdir(parents=True, exist_ok=True)
            artifact_target.write_text(artifact_content, encoding="utf-8")
        return target

    def persist_scan_metadata(
        self,
        config: ScanConfig,
        storage_path: Path,
    ) -> Path:
        output_dir = Path(storage_path)
        output_dir.mkdir(parents=True, exist_ok=True)
        target = output_dir / SCAN_METADATA_FILE_NAME
        target.write_text(
            json.dumps(
                {
                    "scan_label": config.scan_label,
                    "platform": config.platform,
                    "target_type": config.target_type,
                    "stack": config.stack,
                    "project_path": str(config.project_path),
                    "output_path": str(config.output_path),
                },
                indent=2,
                sort_keys=True,
            ),
            encoding="utf-8",
        )
        return target

    @staticmethod
    def _target_path(output_dir: Path, result: ScanResult) -> Path:
        if not result.relative_target_path:
            return output_dir / f"{result.scan_type.value}.txt"

        relative_target = Path(result.relative_target_path)
        if relative_target.is_absolute() or ".." in relative_target.parts:
            relative_target = Path(relative_target.name)

        if not relative_target.suffix:
            relative_target = relative_target.with_suffix(".txt")

        return output_dir / result.scan_type.value / relative_target

    @classmethod
    def _artifact_target_path(
        cls,
        output_dir: Path,
        result: ScanResult,
        relative_path: str,
    ) -> Path:
        relative_target = Path(relative_path)
        if relative_target.is_absolute() or ".." in relative_target.parts:
            relative_target = Path(relative_target.name)
        return output_dir / result.scan_type.value / relative_target
