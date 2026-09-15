"""Map typed Android binary details to Phoenix PDF presentation data."""

from __future__ import annotations

from dataclasses import asdict

from adapters.output.phoenix_report.pdf_report.common import map_functionality
from domain.report import AndroidBinaryReportDetails


def map_android_binary_details(details: AndroidBinaryReportDetails) -> dict[str, object]:
    """Return template-shaped Android binary inventory data."""

    return {
        "certificate": asdict(details.certificate),
        "file_info": asdict(details.file_info),
        "app_info": asdict(details.app_info),
        "application": asdict(details.application),
        "app_components": asdict(details.app_components),
        "functionality": map_functionality(details.functionality),
        "permissions": [asdict(item) for item in details.permissions],
        "hardcoded_values": asdict(details.hardcoded_values),
        "endpoints": [asdict(item) for item in details.endpoints],
    }
