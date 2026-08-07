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
    WEAK_CRYPTO_TERMS = (
        "3des",
        "des",
        "ecb",
        "insecure cryptography",
        "md5",
        "rc2",
        "rc4",
        "sha1",
        "weak crypto",
    )

    def __init__(self, context: NativeIOSScanExtractionContext) -> None:
        insecure_crypto = self._matching_opengrep_entry(
            context,
            self.WEAK_CRYPTO_TERMS,
            "no_utilizes_insecure_cryptography_hits",
        )
        self.uses_uiwebview = self._matching_opengrep_entry(
            context,
            ("uiwebview",),
            "no_uses_uiwebview_hits",
        )
        self.insecure_nanopb_library = self._nanopb_evidence(context)
        self.insecure_nskeyedunarchiver_usage = self._matching_opengrep_entry(
            context,
            ("nskeyedunarchiver",),
            "no_insecure_nskeyedunarchiver_usage_hits",
        )
        self.encodes_data_using_insecure_cryptography = insecure_crypto
        self.utilizes_insecure_cryptography = NativeIOSEvidenceEntry(
            insecure_crypto.present,
            insecure_crypto.evidence,
        )
        self.pbkdf2_iteration_count_below_10k = self._matching_opengrep_entry(
            context,
            ("pbkdf2",),
            "no_pbkdf2_iteration_count_below_10k_hits",
        )
        self.hardcoded_api_keys_in_bundle = self._secret_evidence(context)
        self.insecure_entitlements = self._entitlement_evidence(context)

    @classmethod
    def _matching_opengrep_entry(
        cls,
        context: NativeIOSScanExtractionContext,
        terms: tuple[str, ...],
        absent_evidence: str,
    ) -> NativeIOSEvidenceEntry:
        for result in context.opengrep_results:
            extra = result.get("extra") or {}
            phoenix = (extra.get("metadata") or {}).get("phoenix") or {}
            haystack = " ".join(
                str(value).lower()
                for value in (
                    result.get("check_id"),
                    phoenix.get("title"),
                    phoenix.get("description"),
                    extra.get("message"),
                )
                if value
            )
            if not any(term in haystack for term in terms):
                continue
            evidence = context.first_non_empty(
                extra.get("lines"),
                phoenix.get("description"),
                phoenix.get("title"),
                extra.get("message"),
                result.get("check_id"),
            )
            path = str(result.get("path", "")).strip()
            return NativeIOSEvidenceEntry(True, f"{path}: {evidence}" if path else evidence)
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
