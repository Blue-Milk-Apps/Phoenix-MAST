"""Build native iOS code evidence from source scan outputs."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass

from domain.post_scan.ios.native.scan_extraction_context import NativeIOSScanExtractionContext


@dataclass
class NativeIOSEvidenceEntry:
    present: bool
    evidence: str


@dataclass
class NativeIOSCodeEvidence:
    uses_uiwebview: NativeIOSEvidenceEntry
    insecure_nanopb_library: NativeIOSEvidenceEntry
    insecure_nskeyedunarchiver_usage: NativeIOSEvidenceEntry
    encodes_data_using_insecure_cryptography: NativeIOSEvidenceEntry
    utilizes_insecure_cryptography: NativeIOSEvidenceEntry
    pbkdf2_iteration_count_below_10k: NativeIOSEvidenceEntry
    hardcoded_api_keys_in_bundle: NativeIOSEvidenceEntry
    insecure_entitlements: NativeIOSEvidenceEntry

    INSECURE_ENTITLEMENT_KEYS = frozenset(
        {
            "get-task-allow",
            "com.apple.security.cs.allow-dyld-environment-variables",
            "com.apple.security.cs.allow-unsigned-executable-memory",
            "com.apple.security.cs.disable-executable-page-protection",
            "com.apple.security.cs.disable-library-validation",
        }
    )
    UIWEBVIEW_RULE_IDS = frozenset({"ios-deprecated-api-uiwebview"})
    INSECURE_NSKEYEDUNARCHIVER_RULE_IDS = frozenset({"ios-insecure-serialization-nskeyedunarchiver"})
    INSECURE_CRYPTO_ENCODING_RULE_IDS = frozenset(
        {
            "ios-weak-crypto-md5",
            "ios-weak-crypto-operation-3des",
            "ios-weak-crypto-operation-des",
            "ios-weak-crypto-operation-ecb",
            "ios-weak-crypto-operation-rc4",
            "ios-weak-crypto-sha1",
        }
    )
    INSECURE_CRYPTO_REFERENCE_RULE_IDS = frozenset(
        {
            "ios-weak-crypto-reference-3des",
            "ios-weak-crypto-reference-des",
            "ios-weak-crypto-reference-rc4",
        }
    )
    LOW_PBKDF2_ITERATION_RULE_IDS = frozenset({"ios-pbkdf2-low-iterations"})

    def __init__(self, context: NativeIOSScanExtractionContext) -> None:
        self.uses_uiwebview = self._opengrep_entry_for_rule_ids(
            context,
            self.UIWEBVIEW_RULE_IDS,
            "no_uses_uiwebview_hits",
        )
        self.insecure_nanopb_library = self._nanopb_evidence(context)
        self.insecure_nskeyedunarchiver_usage = self._opengrep_entry_for_rule_ids(
            context,
            self.INSECURE_NSKEYEDUNARCHIVER_RULE_IDS,
            "no_insecure_nskeyedunarchiver_usage_hits",
        )
        self.encodes_data_using_insecure_cryptography = self._opengrep_entry_for_rule_ids(
            context,
            self.INSECURE_CRYPTO_ENCODING_RULE_IDS,
            "no_encodes_data_using_insecure_cryptography_hits",
        )
        self.utilizes_insecure_cryptography = self._opengrep_entry_for_rule_ids(
            context,
            self.INSECURE_CRYPTO_REFERENCE_RULE_IDS,
            "no_utilizes_insecure_cryptography_hits",
        )
        self.pbkdf2_iteration_count_below_10k = self._opengrep_entry_for_rule_ids(
            context,
            self.LOW_PBKDF2_ITERATION_RULE_IDS,
            "no_pbkdf2_iteration_count_below_10k_hits",
        )
        self.hardcoded_api_keys_in_bundle = self._secret_evidence(context)
        self.insecure_entitlements = self._entitlement_evidence(context)

    @staticmethod
    def _opengrep_entry_for_rule_ids(
        context: NativeIOSScanExtractionContext,
        rule_ids: frozenset[str],
        absent_evidence: str,
    ) -> NativeIOSEvidenceEntry:
        matches: set[str] = set()
        for result in context.opengrep_results:
            rule_id = str(result.get("check_id", "")).strip()
            if rule_id not in rule_ids:
                continue
            extra = result.get("extra") or {}
            phoenix = (extra.get("metadata") or {}).get("phoenix") or {}
            evidence = context.first_non_empty(
                extra.get("lines"),
                phoenix.get("description"),
                phoenix.get("title"),
                extra.get("message"),
                result.get("check_id"),
            )
            path = str(result.get("path", "")).strip()
            matches.add(f"{path}: {evidence}" if path else evidence)
        if matches:
            return NativeIOSEvidenceEntry(True, "; ".join(sorted(matches)))
        return NativeIOSEvidenceEntry(False, absent_evidence)

    @staticmethod
    def _nanopb_evidence(context: NativeIOSScanExtractionContext) -> NativeIOSEvidenceEntry:
        for path, package_name, version in context.syft_packages:
            if "nanopb" not in package_name.lower():
                continue
            if not version or re.match(r"^(?:0|1)\.", version):
                label = f"{package_name}@{version}" if version else package_name
                return NativeIOSEvidenceEntry(True, f"{path}: {label}")
        return NativeIOSEvidenceEntry(False, "no_insecure_nanopb_library_hits")

    @staticmethod
    def _secret_evidence(context: NativeIOSScanExtractionContext) -> NativeIOSEvidenceEntry:
        for output_key in ("gitleaks_outputs", "trufflehog_outputs"):
            outputs = context.loaded_outputs.get(output_key) or {}
            if not isinstance(outputs, dict):
                continue
            for path, content in outputs.items():
                text = json.dumps(content, sort_keys=True) if not isinstance(content, str) else content
                lowered = text.lower()
                if any(term in lowered for term in ("api key", "api_key", "apikey", "generic-api-key")):
                    return NativeIOSEvidenceEntry(True, f"{output_key}/{path}")
        return NativeIOSEvidenceEntry(False, "no_hardcoded_api_keys_in_bundle_hits")

    def _entitlement_evidence(self, context: NativeIOSScanExtractionContext) -> NativeIOSEvidenceEntry:
        detected: set[str] = set()
        for document in context.plist_outputs.values():
            plist = document.get("plist")
            if not isinstance(plist, dict):
                continue
            detected.update(key for key in self.INSECURE_ENTITLEMENT_KEYS if plist.get(key) is True)
            detected.update(str(key) for key in plist if str(key).startswith("com.apple.private."))
        if detected:
            return NativeIOSEvidenceEntry(True, ", ".join(sorted(detected)))
        return NativeIOSEvidenceEntry(False, "no_insecure_entitlements_hits")
