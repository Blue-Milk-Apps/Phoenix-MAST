"""Tests for React Native post-scan workflow registration."""

from __future__ import annotations

from pathlib import Path

import pytest

from adapters.post_scan import ReactNativeScanDetailExtractor, ReactNativeScanOutputLoader
from application.mobile_analysis_workflow_service import MobileAnalysisWorkflowService
from application.post_scan_processing_service import PostScanProcessingService
from domain.models import ScanConfig


@pytest.mark.parametrize("platform", ["ANY", "ANDROID", "IOS"])
def test_registers_react_native_source_post_scan_processing_for_each_platform(
    tmp_path: Path,
    platform: str,
) -> None:
    config = ScanConfig(
        project_path=tmp_path,
        output_path=tmp_path / "results",
        mode="source",
        platform=platform,
        stack="REACT_NATIVE",
    )

    service = MobileAnalysisWorkflowService._build_post_scan_processing_service(config)

    assert isinstance(service, PostScanProcessingService)
    assert isinstance(service._scan_output_loader, ReactNativeScanOutputLoader)
    assert isinstance(service._scan_detail_extractor, ReactNativeScanDetailExtractor)
