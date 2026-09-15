"""Create canonical report targets from scan configuration."""

from __future__ import annotations

from domain.models import ScanConfig
from domain.report.models import (
    ReportPlatform,
    ReportStack,
    ReportTarget,
    ReportTargetKind,
    ReportTargetType,
)


class ReportTargetFactory:
    """Convert supported scan configurations to report targets."""

    @staticmethod
    def from_scan_config(scan_config: ScanConfig) -> ReportTarget:
        """Return the canonical report target for a supported scan configuration."""

        target_type = scan_config.target_type.strip().upper()
        platform = str(scan_config.platform).strip().upper()
        stack = str(scan_config.stack).strip().upper()

        match (target_type, platform, stack):
            case ("BINARY", "ANDROID", "ANY"):
                return ReportTarget(
                    target_kind=ReportTargetKind.ANDROID_BINARY,
                    platform=ReportPlatform.ANDROID,
                    target_type=ReportTargetType.BINARY,
                    stack=None,
                )
            case ("BINARY", "IOS", "ANY"):
                return ReportTarget(
                    target_kind=ReportTargetKind.IOS_BINARY,
                    platform=ReportPlatform.IOS,
                    target_type=ReportTargetType.BINARY,
                    stack=None,
                )
            case ("SOURCE", "ANY", "FLUTTER"):
                return ReportTarget(
                    target_kind=ReportTargetKind.FLUTTER_SOURCE,
                    platform=ReportPlatform.FLUTTER,
                    target_type=ReportTargetType.SOURCE,
                    stack=ReportStack.FLUTTER,
                )
            case ("SOURCE", "ANY", "REACT_NATIVE"):
                return ReportTarget(
                    target_kind=ReportTargetKind.REACT_NATIVE_SOURCE,
                    platform=ReportPlatform.REACT_NATIVE,
                    target_type=ReportTargetType.SOURCE,
                    stack=ReportStack.REACT_NATIVE,
                )
            case ("SOURCE", "ANDROID", "NATIVE_ANDROID"):
                return ReportTarget(
                    target_kind=ReportTargetKind.NATIVE_ANDROID_SOURCE,
                    platform=ReportPlatform.ANDROID,
                    target_type=ReportTargetType.SOURCE,
                    stack=ReportStack.NATIVE_ANDROID,
                )
            case ("SOURCE", "IOS", "NATIVE_IOS"):
                return ReportTarget(
                    target_kind=ReportTargetKind.NATIVE_IOS_SOURCE,
                    platform=ReportPlatform.IOS,
                    target_type=ReportTargetType.SOURCE,
                    stack=ReportStack.NATIVE_IOS,
                )
            case _:
                raise ValueError(
                    "Unsupported report target configuration: "
                    f"target_type={target_type}, platform={platform}, stack={stack}"
                )
