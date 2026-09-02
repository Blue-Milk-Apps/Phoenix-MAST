"""Security evidence models for React Native source reports."""

from __future__ import annotations

from domain.post_scan.android.rule_registry import REPORT_RULE_IDS_BY_SECTION as ANDROID_RULE_IDS
from domain.post_scan.flutter.code_evidence import FlutterCodeEvidence
from domain.post_scan.flutter.data_storage_evidence import FlutterDataStorageEvidence
from domain.post_scan.flutter.network_evidence import FlutterNetworkEvidence
from domain.post_scan.flutter.resilience_evidence import FlutterResilienceEvidence
from domain.post_scan.flutter.security_evidence import (
    FlutterEvidenceEntry,
    combine_evidence_entries,
    opengrep_scope_applicable,
    scoped_opengrep_entry,
)
from domain.post_scan.ios.rule_registry import CODE_RULE_IDS_BY_EVIDENCE_KEY as IOS_CODE_RULE_IDS
from domain.post_scan.ios.rule_registry import DATA_STORAGE_RULE_IDS_BY_EVIDENCE_KEY as IOS_STORAGE_RULE_IDS
from domain.post_scan.ios.rule_registry import NETWORK_RULE_IDS_BY_EVIDENCE_KEY as IOS_NETWORK_RULE_IDS
from domain.post_scan.react_native.rule_registry import REPORT_RULE_IDS_BY_SECTION as REACT_NATIVE_RULE_IDS
from domain.post_scan.react_native.scan_extraction_context import ReactNativeScanExtractionContext


class ReactNativeCodeEvidence(FlutterCodeEvidence):
    """Evaluate shared source and embedded-platform code evidence."""

    def __init__(self, context: ReactNativeScanExtractionContext) -> None:
        super().__init__(context)

    @classmethod
    def _rule_entry(
        cls,
        context: ReactNativeScanExtractionContext,
        evidence_key: str,
    ) -> FlutterEvidenceEntry:
        rules_by_scope = {
            "react_native": REACT_NATIVE_RULE_IDS["Code"].get(evidence_key, frozenset()),
            "android": ANDROID_RULE_IDS["Code"].get(evidence_key, frozenset()),
            "ios": IOS_CODE_RULE_IDS.get(evidence_key, frozenset()),
        }
        return _combined_rule_entry(context, evidence_key, rules_by_scope)


class ReactNativeNetworkEvidence(FlutterNetworkEvidence):
    """Evaluate shared source and embedded-platform network evidence."""

    def __init__(self, context: ReactNativeScanExtractionContext) -> None:
        super().__init__(context)

    @staticmethod
    def _rule_entry(
        context: ReactNativeScanExtractionContext,
        evidence_key: str,
    ) -> FlutterEvidenceEntry:
        rules_by_scope = {
            "react_native": REACT_NATIVE_RULE_IDS["Network"].get(evidence_key, frozenset()),
            "android": ANDROID_RULE_IDS["Network"].get(evidence_key, frozenset()),
            "ios": IOS_NETWORK_RULE_IDS.get(evidence_key, frozenset()),
        }
        return _combined_rule_entry(context, evidence_key, rules_by_scope)


class ReactNativeDataStorageEvidence(FlutterDataStorageEvidence):
    """Evaluate shared source and embedded-platform storage evidence."""

    def __init__(self, context: ReactNativeScanExtractionContext) -> None:
        super().__init__(context)

    @staticmethod
    def _rule_entry(
        context: ReactNativeScanExtractionContext,
        evidence_key: str,
    ) -> FlutterEvidenceEntry:
        rules_by_scope = {
            "react_native": REACT_NATIVE_RULE_IDS["Data Storage"].get(evidence_key, frozenset()),
            "android": ANDROID_RULE_IDS["Data Storage"].get(evidence_key, frozenset()),
            "ios": IOS_STORAGE_RULE_IDS.get(evidence_key, frozenset()),
        }
        return _combined_rule_entry(context, evidence_key, rules_by_scope)


class ReactNativeResilienceEvidence(FlutterResilienceEvidence):
    """Evaluate shared embedded-platform resilience evidence."""

    def __init__(self, context: ReactNativeScanExtractionContext) -> None:
        super().__init__(context)


def _combined_rule_entry(
    context: ReactNativeScanExtractionContext,
    evidence_key: str,
    rules_by_scope: dict[str, frozenset[str]],
) -> FlutterEvidenceEntry:
    entries = [
        scoped_opengrep_entry(
            context,
            scope=scope,
            rule_ids=rule_ids,
            absent_evidence=f"no_{evidence_key}_{scope}_hits",
        )
        for scope, rule_ids in rules_by_scope.items()
        if rule_ids and opengrep_scope_applicable(context, scope)
    ]
    return combine_evidence_entries(entries, absent_evidence=f"no_{evidence_key}_hits")
