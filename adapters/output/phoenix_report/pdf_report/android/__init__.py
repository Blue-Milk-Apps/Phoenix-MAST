"""Android PDF presentation mappers."""

from adapters.output.phoenix_report.pdf_report.android.mapper import map_android_binary_details
from adapters.output.phoenix_report.pdf_report.android.source import map_native_android_details

__all__ = ["map_android_binary_details", "map_native_android_details"]
