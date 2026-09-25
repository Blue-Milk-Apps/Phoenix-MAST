"""Functionality inventory from the persisted framework and native YAML catalogs."""

from domain.post_scan.react_native.scan_extraction_context import ReactNativeScanExtractionContext
from domain.post_scan.rule_assessment import RuleFunctionality


class ReactNativeFunctionality(RuleFunctionality):
    def __init__(self, context: ReactNativeScanExtractionContext) -> None:
        super().__init__(context.loaded_outputs.get("opengrep"))
