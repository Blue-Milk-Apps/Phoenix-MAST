from pathlib import Path

import pytest

from domain.models import ScanConfig


@pytest.fixture
def scan_config():
    def _build(tmp_path: Path, rules_path: Path | None = None) -> ScanConfig:
        project_path = tmp_path / "project"
        output_path = tmp_path / "scan-results"
        project_path.mkdir()
        return ScanConfig(
            project_path=project_path,
            output_path=output_path,
            mode="source",
            rules_path=rules_path,
        )

    return _build
