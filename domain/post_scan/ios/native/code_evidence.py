"""Build native iOS code evidence from source scan outputs."""

from __future__ import annotations

import re
from dataclasses import dataclass

from domain.post_scan.ios.native.scan_extraction_context import NativeIOSScanExtractionContext
from domain.post_scan.utilities import summarize_secret_scans


@dataclass(frozen=True)
class NativeIOSEvidenceEntry:
    present: bool | None
    evidence: str
    execution_status: str
    not_evaluated_reason: str = ""

    @classmethod
    def from_matches(cls, matches: list[str], *, complete: bool, reason: str) -> NativeIOSEvidenceEntry:
        """Only a completed evaluation can establish absence; retain partial hits."""
        return cls(
            present=True if matches else False if complete else None,
            evidence="; ".join(dict.fromkeys(matches)),
            execution_status="success" if complete else "partial" if matches else "not_evaluated",
            not_evaluated_reason="" if complete else reason,
        )


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
        outputs = context.loaded_outputs.get("syft_outputs")
        report = outputs.get("sbom.json") if isinstance(outputs, dict) else None
        complete = (
            isinstance(report, dict)
            and not any(report.get(key) for key in ("error", "errors", "skipped"))
            and report.get("success") is not False
            and "raw_output" not in report
        )
        payload = report.get("raw_output", report) if isinstance(report, dict) else None
        collections = (
            [payload[key] for key in ("artifacts", "components") if key in payload] if isinstance(payload, dict) else []
        )
        complete = complete and bool(collections)
        matches = []
        for collection in collections:
            if not isinstance(collection, list):
                complete = False
                continue
            for package in collection:
                if (
                    not isinstance(package, dict)
                    or not isinstance(package.get("name"), str)
                    or not package["name"].strip()
                ):
                    complete = False
                    continue
                package_name = package["name"].strip()
                version = package.get("version", "")
                if not isinstance(version, str):
                    complete = False
                    continue
                if "nanopb" in package_name.lower() and (not version or re.match(r"^(?:0|1)\.", version)):
                    label = f"{package_name}@{version}" if version else package_name
                    matches.append(f"sbom.json: {label}")
        return NativeIOSEvidenceEntry.from_matches(
            matches,
            complete=complete,
            reason="Syft did not provide a complete, readable package inventory",
        )

    @staticmethod
    def _secret_evidence(context: NativeIOSScanExtractionContext) -> NativeIOSEvidenceEntry:
        summaries = summarize_secret_scans(context.loaded_outputs)
        matches = []
        for output_key, detector_key in (("gitleaks_outputs", "RuleID"), ("trufflehog_outputs", "DetectorName")):
            outputs = context.loaded_outputs.get(output_key)
            for path, report in outputs.items() if isinstance(outputs, dict) else ():
                findings = report.get("raw_output") if isinstance(report, dict) else report
                for finding in findings if isinstance(findings, list) else ():
                    if not isinstance(finding, dict):
                        continue
                    detector = finding.get(detector_key)
                    if not isinstance(detector, str) or not detector.strip():
                        continue
                    label = " ".join(
                        str(finding.get(key) or "") for key in (detector_key, "Description", "DetectorDescription")
                    ).lower()
                    if any(term in label for term in ("api key", "api_key", "apikey", "api-key")):
                        matches.append(f"{output_key}/{path}: {detector}")
        incomplete = [summary.scanner for summary in summaries if summary.status != "Completed"]
        return NativeIOSEvidenceEntry.from_matches(
            matches,
            complete=not incomplete,
            reason=f"{', '.join(incomplete)} did not provide complete, readable secret-scanner results",
        )

    def _entitlement_evidence(self, context: NativeIOSScanExtractionContext) -> NativeIOSEvidenceEntry:
        outputs = context.loaded_outputs.get("plist_outputs")
        outputs = outputs if isinstance(outputs, dict) else {}
        index = context.loaded_outputs.get("plist_index")
        entries = index.get("plists") if isinstance(index, dict) else None
        complete = (
            isinstance(index, dict)
            and index.get("parse_failures") == 0
            and isinstance(entries, list)
            and bool(entries)
            and index.get("plist_count") == len(entries)
        )
        for entry in entries if isinstance(entries, list) else ():
            if not isinstance(entry, dict) or entry.get("parse_status") != "success":
                complete = False
            elif not entry.get("skipped"):
                path = entry.get("output_path")
                if not isinstance(path, str) or not isinstance(outputs.get(path), dict):
                    complete = False
        detected: set[str] = set()
        readable = False
        for document in outputs.values():
            plist = document.get("plist") if isinstance(document, dict) else None
            if not isinstance(plist, dict):
                complete = False
                continue
            readable = True
            detected.update(key for key in self.INSECURE_ENTITLEMENT_KEYS if plist.get(key) is True)
            detected.update(str(key) for key in plist if str(key).startswith("com.apple.private."))
        return NativeIOSEvidenceEntry.from_matches(
            sorted(detected),
            complete=complete and readable,
            reason="The source plist inventory is missing, incomplete, or contains unreadable files",
        )
