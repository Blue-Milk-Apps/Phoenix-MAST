"""iOS binary post-scan adapters."""

from adapters.post_scan.ios.binary.scan_detail_extractor import IOSBinaryScanDetailExtractor
from adapters.post_scan.ios.binary.scan_output_loader import IOSBinaryScanOutputLoader

__all__ = ["IOSBinaryScanDetailExtractor", "IOSBinaryScanOutputLoader"]
