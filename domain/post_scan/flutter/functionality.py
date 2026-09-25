"""Functionality inventory from the persisted framework and native YAML catalogs."""

from domain.post_scan.flutter.scan_extraction_context import FlutterScanExtractionContext
from domain.post_scan.rule_assessment import RuleFunctionality


class FlutterFunctionality(RuleFunctionality):
    def __init__(self, context: FlutterScanExtractionContext) -> None:
        super().__init__(context.loaded_outputs.get("opengrep"))
