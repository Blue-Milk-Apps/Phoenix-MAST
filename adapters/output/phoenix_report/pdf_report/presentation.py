"""PDF presentation rules derived from a canonical report target."""

from __future__ import annotations

from dataclasses import dataclass

from domain.report import ReportTargetKind, ReportTargetType


@dataclass(frozen=True)
class PdfPresentation:
    """Labels and visibility decisions for a PDF report."""

    assessment_label: str
    assessment_title: str
    target_label: str
    target_information_heading: str
    target_type: ReportTargetType
    show_file_hashes: bool
    show_ios_binary_analysis: bool

    @classmethod
    def for_target_kind(cls, target_kind: ReportTargetKind) -> "PdfPresentation":
        """Return the presentation rules for one supported report family."""

        target_type = (
            ReportTargetType.BINARY
            if target_kind in {ReportTargetKind.ANDROID_BINARY, ReportTargetKind.IOS_BINARY}
            else ReportTargetType.SOURCE
        )
        source_label = {
            ReportTargetKind.FLUTTER_SOURCE: "Flutter Source Code",
            ReportTargetKind.REACT_NATIVE_SOURCE: "React Native Source Code",
        }.get(target_kind, "Source Code")
        source_heading = {
            ReportTargetKind.FLUTTER_SOURCE: "Flutter Project Information",
            ReportTargetKind.REACT_NATIVE_SOURCE: "React Native Project Information",
        }.get(target_kind, "Source Project Information")
        return cls(
            assessment_label=source_label if target_type == ReportTargetType.SOURCE else "Binary",
            assessment_title=(
                f"{source_label} Vulnerability Assessment"
                if target_type == ReportTargetType.SOURCE
                else "Application Vulnerability Assessment"
            ),
            target_label="Project Name" if target_type == ReportTargetType.SOURCE else "File Name",
            target_information_heading=source_heading if target_type == ReportTargetType.SOURCE else "File Information",
            target_type=target_type,
            show_file_hashes=target_type == ReportTargetType.BINARY,
            show_ios_binary_analysis=target_kind == ReportTargetKind.IOS_BINARY,
        )
