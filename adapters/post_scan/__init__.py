"""Adapters for post-scan processing."""

from adapters.post_scan.android.native import NativeAndroidScanDetailExtractor, NativeAndroidScanOutputLoader
from adapters.post_scan.android_binary_scan_detail_extractor import (
    AndroidBinaryScanDetailExtractor,
)
from adapters.post_scan.android_binary_scan_output_loader import (
    AndroidBinaryScanOutputLoader,
)
from adapters.post_scan.ios.binary import IOSBinaryScanDetailExtractor, IOSBinaryScanOutputLoader
from adapters.post_scan.ios.native import NativeIOSScanDetailExtractor, NativeIOSScanOutputLoader

__all__ = [
    "AndroidBinaryScanDetailExtractor",
    "AndroidBinaryScanOutputLoader",
    "IOSBinaryScanDetailExtractor",
    "IOSBinaryScanOutputLoader",
    "NativeAndroidScanDetailExtractor",
    "NativeAndroidScanOutputLoader",
    "NativeIOSScanDetailExtractor",
    "NativeIOSScanOutputLoader",
]
