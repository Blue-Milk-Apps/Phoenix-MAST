"""Map typed iOS binary details to Phoenix PDF presentation data."""

from __future__ import annotations

from dataclasses import asdict

from adapters.output.phoenix_report.pdf_report.common import map_functionality
from domain.report import IOSBinaryReportDetails


def map_ios_binary_details(details: IOSBinaryReportDetails) -> dict[str, object]:
    """Return template-shaped iOS binary inventory data."""

    return {
        "file_info": asdict(details.file_info),
        "app_info": asdict(details.app_info),
        "ipa_binary_protections": [
            {
                "protection": name.replace("_", " ").title(),
                "status": "Present" if value else "Not Present",
                "severity": "Info" if value else "Medium",
                "description": "Protection detected." if value else "Protection not detected.",
            }
            for name, value in asdict(details.binary_evidence).items()
            if value is not None
        ],
        "url_schemes": [asdict(item) for item in details.url_schemes],
        "functionality": map_functionality(details.functionality),
        "third_party_sdks": {
            item.category: {name: True for name in item.sdk_names} for item in details.third_party_sdks
        },
        "permissions": [asdict(item) for item in details.permissions],
        "hardcoded_values": asdict(details.hardcoded_values),
        "endpoints": [asdict(item) for item in details.endpoints],
    }
