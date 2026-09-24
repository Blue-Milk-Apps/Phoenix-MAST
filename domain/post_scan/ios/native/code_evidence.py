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
    insecure_nanopb_library: NativeIOSEvidenceEntry
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

    def __init__(self, context: NativeIOSScanExtractionContext) -> None:
        self.insecure_nanopb_library = self._nanopb_evidence(context)
        self.hardcoded_api_keys_in_bundle = self._secret_evidence(context)
        self.insecure_entitlements = self._entitlement_evidence(context)

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
