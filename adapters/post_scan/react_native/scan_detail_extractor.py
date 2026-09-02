"""React Native source detail extractor for post-scan processing."""

from __future__ import annotations

from dataclasses import asdict
from typing import Any

from domain.post_scan.react_native.app_components import ReactNativeAppComponents
from domain.post_scan.react_native.app_info import ReactNativeAppInfo
from domain.post_scan.react_native.application import ReactNativeApplication
from domain.post_scan.react_native.dependency_inventory import ReactNativeDependencyInventory
from domain.post_scan.react_native.evidence import (
    ReactNativeCodeEvidence,
    ReactNativeDataStorageEvidence,
    ReactNativeNetworkEvidence,
    ReactNativeResilienceEvidence,
)
from domain.post_scan.react_native.file_info import ReactNativeFileInfo
from domain.post_scan.react_native.hardcoded_values import ReactNativeHardcodedValues
from domain.post_scan.react_native.links import ReactNativeDeepLinks, ReactNativeURLSchemes
from domain.post_scan.react_native.meta import ReactNativeMeta
from domain.post_scan.react_native.permissions import ReactNativePermissions
from domain.post_scan.react_native.platform_inventory import ReactNativePlatformInventory
from domain.post_scan.react_native.scan_extraction_context import ReactNativeScanExtractionContext
from ports.post_scan.scan_detail_extractor_port import ScanDetailExtractorPort


class ReactNativeScanDetailExtractor(ScanDetailExtractorPort):
    """Assemble report-ready React Native source sections."""

    def extract_sections(self, loaded_outputs: dict[str, Any]) -> dict[str, Any]:
        context = ReactNativeScanExtractionContext(loaded_outputs)
        url_schemes = ReactNativeURLSchemes(context)
        sections = {
            "meta": asdict(ReactNativeMeta(context)),
            "file_info": asdict(ReactNativeFileInfo(context)),
            "app_info": asdict(ReactNativeAppInfo(context)),
            "platform_inventory": asdict(ReactNativePlatformInventory(context)),
            "dependency_inventory": asdict(ReactNativeDependencyInventory(context)),
            "application": asdict(ReactNativeApplication(context)),
            "app_components": asdict(ReactNativeAppComponents(context)),
            "permissions": ReactNativePermissions(context).items,
            "deep_links": asdict(ReactNativeDeepLinks(context)),
            "url_schemes": url_schemes.items,
            "queried_url_schemes": url_schemes.queried_schemes,
        }

        hardcoded_values = ReactNativeHardcodedValues(context)
        if hardcoded_values.assessed or hardcoded_values.secrets:
            sections["hardcoded_values"] = {
                "urls": hardcoded_values.urls,
                "emails": hardcoded_values.emails,
                "secrets": hardcoded_values.secrets,
            }
            sections["endpoints"] = []

        evidence_models = (
            ("code_evidence", ReactNativeCodeEvidence(context)),
            ("network_evidence", ReactNativeNetworkEvidence(context)),
            ("data_storage_evidence", ReactNativeDataStorageEvidence(context)),
            ("resilience_evidence", ReactNativeResilienceEvidence(context)),
        )
        for section_name, model in evidence_models:
            evidence = asdict(model)
            evidence.pop("assessed", None)
            sections[section_name] = evidence

        return sections
