"""Native iOS source post-scan adapters."""

from adapters.post_scan.ios.native.scan_detail_extractor import NativeIOSScanDetailExtractor
from adapters.post_scan.ios.native.scan_output_loader import NativeIOSScanOutputLoader

__all__ = ["NativeIOSScanDetailExtractor", "NativeIOSScanOutputLoader"]
