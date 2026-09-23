"""Native iOS source detail extractor for post-scan processing."""

from __future__ import annotations

from dataclasses import asdict
from typing import Any

from domain.post_scan.ios.common.data_storage_evidence import IOSDataStorageEvidence
from domain.post_scan.ios.common.functionality import IOSFunctionality
from domain.post_scan.ios.common.network_evidence import IOSNetworkEvidence
from domain.post_scan.ios.common.permissions import IOSPermissions
from domain.post_scan.ios.common.third_party_sdks import IOSThirdPartySDKs
from domain.post_scan.ios.native.app_info import NativeIOSAppInfo
from domain.post_scan.ios.native.code_evidence import NativeIOSCodeEvidence
from domain.post_scan.ios.native.file_info import NativeIOSFileInfo
from domain.post_scan.ios.native.meta import NativeIOSMeta
from domain.post_scan.ios.native.scan_extraction_context import NativeIOSScanExtractionContext
from domain.post_scan.ios.native.url_schemes import NativeIOSURLSchemes
from domain.post_scan.ios.rule_registry import IOS_RULE_REGISTRY, IOSRuleDisposition
from ports.post_scan.scan_detail_extractor_port import ScanDetailExtractorPort


class NativeIOSScanDetailExtractor(ScanDetailExtractorPort):
    """Assemble native iOS report sections from source-only evidence models."""

    def extract_sections(self, loaded_outputs: dict[str, Any]) -> dict[str, Any]:
        context = NativeIOSScanExtractionContext(loaded_outputs)
        functionality = asdict(IOSFunctionality(loaded_outputs))
        third_party_sdks = asdict(IOSThirdPartySDKs(loaded_outputs))

        sections = {
            "meta": asdict(NativeIOSMeta(context)),
            "file_info": asdict(NativeIOSFileInfo(context)),
            "app_info": asdict(NativeIOSAppInfo(context)),
            "url_schemes": NativeIOSURLSchemes(context).items,
            "functionality": {key.replace("_", " "): value for key, value in functionality.items()},
            "third_party_sdks": {key.replace("_", " "): value for key, value in third_party_sdks.items()},
            "permissions": IOSPermissions(loaded_outputs).items,
            "code_evidence": asdict(NativeIOSCodeEvidence(context)),
            "network_evidence": asdict(IOSNetworkEvidence(loaded_outputs)),
            "data_storage_evidence": asdict(IOSDataStorageEvidence(loaded_outputs)),
            "hardcoded_values": {"urls": [], "emails": [], "secrets": []},
            "endpoints": [],
        }
        manual_review = self._manual_review(context)
        if manual_review["assessed"] or manual_review["findings"]:
            sections["manual_review"] = manual_review
        return sections

    @staticmethod
    def _manual_review(context: NativeIOSScanExtractionContext) -> dict[str, Any]:
        raw_rules = {
            rule_id: mapping
            for rule_id, mapping in IOS_RULE_REGISTRY.items()
            if mapping.disposition is IOSRuleDisposition.RAW_ONLY
        }
        opengrep = context.loaded_outputs.get("opengrep")
        results = opengrep.get("results") if isinstance(opengrep, dict) else None
        assessed = isinstance(opengrep, dict) and isinstance(results, list) and opengrep.get("success") is not False
        findings: list[dict[str, str]] = []
        for result in results or []:
            if not isinstance(result, dict):
                continue
            rule_id = context.first_non_empty(result.get("check_id"))
            mapping = raw_rules.get(rule_id)
            if mapping is None:
                continue
            extra = result.get("extra") if isinstance(result.get("extra"), dict) else {}
            metadata = extra.get("metadata") if isinstance(extra.get("metadata"), dict) else {}
            phoenix = metadata.get("phoenix") if isinstance(metadata.get("phoenix"), dict) else {}
            location = context.first_non_empty(result.get("path"))
            start = result.get("start") if isinstance(result.get("start"), dict) else {}
            line = start.get("line")
            if location and line not in (None, ""):
                location = f"{location}:{line}"
            findings.append(
                {
                    "rule_id": rule_id,
                    "scope": "ios",
                    "severity": context.first_non_empty(phoenix.get("severity"), "Info"),
                    "reason": mapping.reason,
                    "location": location,
                    "message": context.first_non_empty(
                        phoenix.get("description"),
                        phoenix.get("title"),
                        extra.get("message"),
                        extra.get("lines"),
                        rule_id,
                    ),
                }
            )

        scan_metadata = context.scan_metadata
        configured = scan_metadata.get("configured_rule_ids")
        configured_ids = (
            {str(rule_id).strip() for rule_id in configured if str(rule_id).strip()}
            if isinstance(configured, list)
            else set()
        )
        fully_assessed = assessed and (not configured_ids or set(raw_rules) <= configured_ids)
        unique_findings: list[dict[str, str]] = []
        seen_findings: set[tuple[tuple[str, str], ...]] = set()
        for finding in findings:
            key = tuple(sorted(finding.items()))
            if key in seen_findings:
                continue
            seen_findings.add(key)
            unique_findings.append(finding)
        return {
            "assessed": assessed,
            "fully_assessed": fully_assessed,
            "assessed_scopes": ["ios"] if assessed else [],
            "findings": unique_findings,
        }
