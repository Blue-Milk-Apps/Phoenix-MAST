"""Flutter source detail extractor for post-scan processing."""

from __future__ import annotations

from dataclasses import asdict
from typing import Any, Mapping

from domain.post_scan.android.rule_registry import REPORT_RULE_IDS_BY_SECTION as ANDROID_RULES
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
from domain.post_scan.flutter.rule_registry import REPORT_RULE_IDS_BY_SECTION as FLUTTER_RULES
from domain.post_scan.flutter.security_evidence import opengrep_scope_applicable
from domain.post_scan.ios.rule_registry import REPORT_RULE_IDS_BY_SECTION as IOS_RULES
from domain.report import AssessmentStatus
from ports.post_scan.scan_detail_extractor_port import ScanDetailExtractorPort


class FlutterScanDetailExtractor(ScanDetailExtractorPort):
    """Assemble report-ready Flutter source sections."""

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
        sections["functionality"] = functionality.items
        sections["platform_inventory"]["functionality_platform_assessments"] = functionality.platform_assessments
        sections["platform_inventory"]["security_check_platform_assessments"] = self._security_platform_assessments(
            context
        )

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
            evidence = asdict(model)
            evidence.pop("assessed", None)
            sections[section_name] = evidence

        return sections

    @staticmethod
    def _security_platform_assessments(context: FlutterScanExtractionContext) -> dict[str, dict[str, dict[str, Any]]]:
        """Retain scoped OpenGrep outcomes for later report generation."""

        registries = {"flutter": FLUTTER_RULES, "android": ANDROID_RULES, "ios": IOS_RULES}
        keys = {
            evidence_key for registry in registries.values() for groups in registry.values() for evidence_key in groups
        }
        output: dict[str, dict[str, dict[str, Any]]] = {}
        for key in sorted(keys):
            rows: dict[str, dict[str, Any]] = {}
            for scope, registry in registries.items():
                rule_ids = frozenset(
                    rule_id
                    for groups in registry.values()
                    for evidence_key, values in groups.items()
                    if evidence_key == key
                    for rule_id in values
                )
                if not rule_ids or not opengrep_scope_applicable(context, scope):
                    continue
                matches = [
                    result
                    for result in context.opengrep_results_for_scope(scope)
                    if context.first_non_empty(result.get("check_id")) in rule_ids
                ]
                if matches:
                    evidence = [FlutterScanDetailExtractor._finding_location(context, result) for result in matches]
                    evidence = list(dict.fromkeys(item for item in evidence if item))
                    rows[scope] = {
                        "status": AssessmentStatus.PRESENT.value,
                        "explanation": "; ".join(evidence[:5]),
                        "evidence": evidence[:10],
                    }
                elif context.opengrep_scope_assessed(scope) and rule_ids <= context.opengrep_configured_rule_ids(scope):
                    rows[scope] = {
                        "status": AssessmentStatus.NOT_PRESENT.value,
                        "explanation": f"No {scope} source evidence matched {key.replace('_', ' ')}.",
                        "evidence": [],
                    }
                else:
                    rows[scope] = {
                        "status": AssessmentStatus.NOT_EVALUATED.value,
                        "explanation": "Required platform scan evidence was unavailable.",
                        "evidence": [],
                    }
            if rows:
                output[key] = rows
        return output

    @staticmethod
    def _finding_location(context: FlutterScanExtractionContext, result: Mapping[str, Any]) -> str:
        path = context.first_non_empty(result.get("path"))
        start = result.get("start")
        line = start.get("line") if isinstance(start, Mapping) else None
        return f"{path}:{line}" if path and line not in (None, "") else path
