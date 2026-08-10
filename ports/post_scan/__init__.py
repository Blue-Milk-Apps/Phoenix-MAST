"""Ports for post-scan processing."""

from ports.post_scan.scan_detail_extractor_port import ScanDetailExtractorPort
from ports.post_scan.scan_output_loader_port import ScanOutputLoaderPort

__all__ = ["ScanDetailExtractorPort", "ScanOutputLoaderPort"]
