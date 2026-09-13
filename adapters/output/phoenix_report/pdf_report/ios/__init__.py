"""iOS PDF presentation mappers."""

from adapters.output.phoenix_report.pdf_report.ios.mapper import map_ios_binary_details
from adapters.output.phoenix_report.pdf_report.ios.source import map_native_ios_details

__all__ = ["map_ios_binary_details", "map_native_ios_details"]
