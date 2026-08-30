"""Flutter source detail extractor for post-scan processing."""

from __future__ import annotations

from dataclasses import asdict
from typing import Any

from domain.post_scan.flutter import (
    FlutterAppComponents,
    FlutterAppInfo,
    FlutterApplication,
    FlutterCodeEvidence,
    FlutterDataStorageEvidence,
    FlutterDeepLinks,
    FlutterDependencyInventory,
    FlutterFileInfo,
    FlutterFunctionality,
    FlutterHardcodedValues,
    FlutterManualReviewInventory,
    FlutterMeta,
    FlutterNetworkEvidence,
    FlutterPermissions,
    FlutterPlatformInventory,
    FlutterResilienceEvidence,
    FlutterScanExtractionContext,
    FlutterURLSchemes,
)
from ports.post_scan.scan_detail_extractor_port import ScanDetailExtractorPort


class FlutterScanDetailExtractor(ScanDetailExtractorPort):
    """Assemble Flutter source metadata and inventory report sections."""

    def extract_sections(self, loaded_outputs: dict[str, Any]) -> dict[str, Any]:
        context = FlutterScanExtractionContext(loaded_outputs)
        url_schemes = FlutterURLSchemes(context)
        sections = {
            "meta": asdict(FlutterMeta(context)),
            "file_info": asdict(FlutterFileInfo(context)),
            "app_info": asdict(FlutterAppInfo(context)),
            "platform_inventory": asdict(FlutterPlatformInventory(context)),
            "dependency_inventory": asdict(FlutterDependencyInventory(context)),
            "application": asdict(FlutterApplication(context)),
            "app_components": asdict(FlutterAppComponents(context)),
            "permissions": FlutterPermissions(context).items,
            "deep_links": asdict(FlutterDeepLinks(context)),
            "url_schemes": url_schemes.items,
            "queried_url_schemes": url_schemes.queried_schemes,
        }

        functionality = FlutterFunctionality(context)
        if functionality.assessed:
            sections["functionality"] = functionality.items

        hardcoded_values = FlutterHardcodedValues(context)
        if hardcoded_values.assessed or hardcoded_values.secrets:
            sections["hardcoded_values"] = {
                "urls": hardcoded_values.urls,
                "emails": hardcoded_values.emails,
                "secrets": hardcoded_values.secrets,
            }
            sections["endpoints"] = []

        manual_review = FlutterManualReviewInventory(context)
        if manual_review.assessed or manual_review.findings:
            sections["manual_review"] = asdict(manual_review)

        evidence_models = (
            ("code_evidence", FlutterCodeEvidence(context)),
            ("network_evidence", FlutterNetworkEvidence(context)),
            ("data_storage_evidence", FlutterDataStorageEvidence(context)),
            ("resilience_evidence", FlutterResilienceEvidence(context)),
        )
        for section_name, model in evidence_models:
            if not model.assessed:
                continue
            evidence = asdict(model)
            evidence.pop("assessed", None)
            sections[section_name] = evidence

        return sections
