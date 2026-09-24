"""Build default iOS code evidence section."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

from domain.post_scan.ios.binary.ipa_binary_evidence import IOSIPABinaryEvidence
from domain.post_scan.ios.common.evidence import EvidenceEntry
from domain.post_scan.utilities import first_non_empty


@dataclass
class IOSCodeEvidence:
    uses_uiwebview: EvidenceEntry
    insecure_nanopb_library: EvidenceEntry
    insecure_nskeyedunarchiver_usage: EvidenceEntry
    missing_arc: EvidenceEntry
    pic_not_enabled: EvidenceEntry
    stack_canaries_not_enabled: EvidenceEntry
    insecure_api_usage_in_binary: EvidenceEntry
    malloc_instead_of_calloc: EvidenceEntry
    encodes_data_using_insecure_cryptography: EvidenceEntry
    utilizes_insecure_cryptography: EvidenceEntry
    pbkdf2_iteration_count_below_10k: EvidenceEntry
    hardcoded_api_keys_in_bundle: EvidenceEntry
    insecure_entitlements: EvidenceEntry

    DANGEROUS_C_IMPORTS = ("_fopen", "_memcpy", "_strcpy", "_strncpy", "_sscanf")
    CONFIRMED_WEAK_CRYPTO_TERMS = (
        "md5",
        "sha1",
        "des",
        "3des",
        "tripledes",
        "rc2",
        "rc4",
        "ecb",
    )
    CONFIRMED_CRYPTO_OPERATION_TERMS = (
        "encode",
        "encoding",
        "encrypt",
        "encryption",
        "decrypt",
        "decryption",
        "hash",
        "hashing",
        "digest",
        "cccrypt",
        "pbkdf2",
        "insecure operation",
    )
    OPERATIONAL_WEAK_CRYPTO_TERMS = (
        "kccalgdes",
        "des",
        "3des",
        "tripledes",
        "rc2",
        "rc4",
    )
    PBKDF2_ITERATION_PATTERN = re.compile(r"(?i)(?:pbkdf2|iteration(?:s| count)?)\D{0,20}(\d{3,})")
    INSECURE_ENTITLEMENT_KEYS = (
        "get-task-allow",
        "com.apple.security.cs.disable-library-validation",
        "com.apple.security.cs.allow-unsigned-executable-memory",
        "com.apple.security.cs.allow-dyld-environment-variables",
        "com.apple.security.cs.disable-executable-page-protection",
    )
    NANOPB_VULNERABLE_VERSION_PATTERN = re.compile(r"^(0\.|1\.)")

    def __init__(self, loaded_outputs: dict[str, Any]) -> None:
        ipa_binary_evidence = IOSIPABinaryEvidence(loaded_outputs)
        imported_functions = self._main_imported_functions(loaded_outputs)
        strings_outputs = loaded_outputs.get("strings_outputs") or {}
        self.uses_uiwebview = EvidenceEntry(None, "Evaluated through configured binary YAML rules.")
        self.insecure_nanopb_library = self._name_heuristic_entry(
            loaded_outputs, "no_insecure_nanopb_library_hits", "nanopb"
        )
        self.insecure_nskeyedunarchiver_usage = EvidenceEntry(None, "Evaluated through configured binary YAML rules.")
        self.missing_arc = self._binary_protection_inverse_entry(
            ipa_binary_evidence.arc,
            "no_missing_arc_hits",
            "main Mach-O imports do not expose _objc_release or _swift_release",
        )
        self.pic_not_enabled = self._binary_protection_inverse_entry(
            ipa_binary_evidence.pie, "no_pic_not_enabled_hits", "PIE flag not detected in main Mach-O metadata"
        )
        self.stack_canaries_not_enabled = self._binary_protection_inverse_entry(
            ipa_binary_evidence.stack_canary,
            "no_stack_canaries_not_enabled_hits",
            "main Mach-O imports do not expose ___stack_chk_fail and ___stack_chk_guard",
        )
        self.insecure_api_usage_in_binary = self._import_match_entry(
            imported_functions, self.DANGEROUS_C_IMPORTS, "no_insecure_api_usage_in_binary_hits"
        )
        self.malloc_instead_of_calloc = self._import_match_entry(
            imported_functions, ("_malloc",), "no_malloc_instead_of_calloc_hits"
        )
        self.encodes_data_using_insecure_cryptography = EvidenceEntry(
            None, "Evaluated through configured binary YAML rules."
        )
        self.utilizes_insecure_cryptography = self._crypto_entry(
            imported_functions,
            strings_outputs,
            "no_utilizes_insecure_cryptography_hits",
            term_candidates=self.OPERATIONAL_WEAK_CRYPTO_TERMS,
        )
        self.pbkdf2_iteration_count_below_10k = EvidenceEntry(None, "Evaluated through configured binary YAML rules.")
        self.hardcoded_api_keys_in_bundle = self._hardcoded_api_keys_entry(
            loaded_outputs, "no_hardcoded_api_keys_in_bundle_hits"
        )
        self.insecure_entitlements = self._insecure_entitlements_entry(loaded_outputs, "no_insecure_entitlements_hits")

    @staticmethod
    def _entry(present: bool, evidence: str, absent_evidence: str) -> EvidenceEntry:
        return EvidenceEntry(present, evidence if present else absent_evidence)

    @classmethod
    def _binary_protection_inverse_entry(
        cls,
        protection_present: bool,
        absent_evidence: str,
        present_evidence: str,
    ) -> EvidenceEntry:
        return cls._entry(not protection_present, present_evidence, absent_evidence)

    @classmethod
    def _import_match_entry(
        cls,
        imported_functions: set[str],
        candidates: tuple[str, ...],
        absent_evidence: str,
    ) -> EvidenceEntry:
        matches = sorted(symbol for symbol in candidates if symbol in imported_functions)
        return cls._entry(bool(matches), ", ".join(matches), absent_evidence)

    @classmethod
    def _crypto_entry(
        cls,
        imported_functions: set[str],
        strings_outputs: Any,
        absent_evidence: str,
        *,
        term_candidates: tuple[str, ...],
    ) -> EvidenceEntry:
        candidates: set[str] = set()
        for symbol in imported_functions:
            lowered = symbol.lower()
            if any((term in lowered for term in term_candidates)):
                candidates.add(symbol)
        if isinstance(strings_outputs, dict):
            for content in strings_outputs.values():
                text = str(content or "")
                lowered = text.lower()
                for term in term_candidates:
                    if term in lowered:
                        candidates.add(term)
        return cls._entry(bool(candidates), ", ".join(sorted(candidates)), absent_evidence)

    @classmethod
    def _hardcoded_api_keys_entry(cls, loaded_outputs: dict[str, Any], absent_evidence: str) -> EvidenceEntry:
        candidates: list[str] = []
        for key in ("trufflehog_outputs", "gitleaks_outputs"):
            outputs = loaded_outputs.get(key) or {}
            if not isinstance(outputs, dict):
                continue
            for path, content in outputs.items():
                if isinstance(content, list):
                    structured = cls._secret_findings_from_list(path, content)
                    if structured:
                        candidates.extend(structured)
                        continue
                text = str(content or "")
                for line in text.splitlines():
                    lowered = line.lower()
                    if "api key" in lowered or "apikey" in lowered or "secret keyword" in lowered:
                        candidates.append(f"{path}: {line.strip()}")
                        break
        evidence = "; ".join(candidates[:5])
        return cls._entry(bool(candidates), evidence, absent_evidence)

    @classmethod
    def _insecure_entitlements_entry(cls, loaded_outputs: dict[str, Any], absent_evidence: str) -> EvidenceEntry:
        detected: list[str] = []
        for document in (loaded_outputs.get("ipsw_outputs") or {}).values():
            if not isinstance(document, dict):
                continue
            analysis = document.get("analysis") or {}
            entitlements = analysis.get("entitlements") if isinstance(analysis, dict) else {}
            values = entitlements.get("values") if isinstance(entitlements, dict) else {}
            if not isinstance(values, dict):
                continue
            for key in cls.INSECURE_ENTITLEMENT_KEYS:
                if values.get(key) is True:
                    detected.append(key)
            for key in values:
                if str(key).startswith("com.apple.private."):
                    detected.append(str(key))
        evidence = ", ".join(sorted(set(detected)))
        return cls._entry(bool(detected), evidence, absent_evidence)

    @classmethod
    def _name_heuristic_entry(cls, loaded_outputs: dict[str, Any], absent_evidence: str, needle: str) -> EvidenceEntry:
        syft_entry = cls._syft_package_entry(loaded_outputs, absent_evidence, needle)
        if syft_entry.present:
            return syft_entry

        lowered_needle = needle.lower()
        for document in (loaded_outputs.get("lief_outputs") or {}).values():
            if not isinstance(document, dict):
                continue
            binary = document.get("binary") or {}
            if not isinstance(binary, dict):
                continue
            names = [str(binary.get("name", "")).strip()]
            for slice_document in binary.get("slices") or []:
                if not isinstance(slice_document, dict):
                    continue
                names.extend(str(item).strip() for item in (slice_document.get("libraries") or []))
            for name in names:
                if lowered_needle in name.lower():
                    return cls._entry(True, name, absent_evidence)
        return cls._entry(False, "", absent_evidence)

    @classmethod
    def _syft_package_entry(cls, loaded_outputs: dict[str, Any], absent_evidence: str, needle: str) -> EvidenceEntry:
        packages = cls._syft_packages(loaded_outputs)
        lowered_needle = needle.lower()
        matches: list[str] = []
        for package_name, version in packages:
            if lowered_needle not in package_name.lower():
                continue
            if version and cls.NANOPB_VULNERABLE_VERSION_PATTERN.match(version):
                matches.append(f"{package_name}@{version}")
            elif not version:
                matches.append(package_name)
        return cls._entry(bool(matches), ", ".join(matches), absent_evidence)

    @classmethod
    def _syft_packages(cls, loaded_outputs: dict[str, Any]) -> list[tuple[str, str]]:
        outputs = loaded_outputs.get("syft_outputs") or {}
        if not isinstance(outputs, dict):
            return []

        packages: list[tuple[str, str]] = []
        for content in outputs.values():
            if not isinstance(content, dict):
                continue
            components = content.get("components")
            if isinstance(components, list):
                for component in components:
                    if not isinstance(component, dict):
                        continue
                    name = str(component.get("name", "")).strip()
                    version = str(component.get("version", "")).strip()
                    if name:
                        packages.append((name, version))
            artifacts = content.get("artifacts")
            if isinstance(artifacts, list):
                for artifact in artifacts:
                    if not isinstance(artifact, dict):
                        continue
                    name = str(artifact.get("name", "")).strip()
                    version = str(artifact.get("version", "")).strip()
                    if name:
                        packages.append((name, version))
        return packages

    @staticmethod
    def _secret_findings_from_list(path: str, findings: list[Any]) -> list[str]:
        matches: list[str] = []
        for finding in findings:
            if not isinstance(finding, dict):
                continue
            detector = str(finding.get("DetectorName", "")).strip()
            rule = str(finding.get("RuleID", "")).strip()
            description = str(finding.get("Description", "")).strip()
            title = first_non_empty(detector, rule, description)
            lowered = f"{detector} {rule} {description}".lower()
            if "api key" not in lowered and "apikey" not in lowered and "secret keyword" not in lowered:
                continue
            location = first_non_empty(
                (finding.get("SourceMetadata") or {}).get("Data", {}).get("Filesystem", {}).get("file"),
                finding.get("File"),
            )
            start_line = first_non_empty(
                (finding.get("SourceMetadata") or {}).get("Data", {}).get("Filesystem", {}).get("line"),
                finding.get("StartLine"),
                finding.get("Line"),
            )
            end_line = first_non_empty(finding.get("EndLine"))
            line_suffix = ""
            if start_line and end_line and str(start_line) != str(end_line):
                line_suffix = f"{start_line}-{end_line}"
            elif start_line:
                line_suffix = str(start_line)
            suffix = f"{location}:{line_suffix}" if location and line_suffix else first_non_empty(location)
            matches.append(f"{path}: {title}" + (f" ({suffix})" if suffix else ""))
        return matches

    @staticmethod
    def _main_imported_functions(loaded_outputs: dict[str, Any]) -> set[str]:
        imported_functions: set[str] = set()
        lief_outputs = loaded_outputs.get("lief_outputs") or {}
        if not isinstance(lief_outputs, dict):
            return imported_functions
        primary_documents = [
            document
            for document in lief_outputs.values()
            if isinstance(document, dict)
            and str(((document.get("binary") or {}).get("kind", ""))).strip().lower() == "main"
        ]
        documents = primary_documents or [document for document in lief_outputs.values() if isinstance(document, dict)]
        for document in documents:
            binary = document.get("binary") or {}
            if not isinstance(binary, dict):
                continue
            for slice_document in binary.get("slices") or []:
                if not isinstance(slice_document, dict):
                    continue
                for symbol in slice_document.get("imported_functions") or []:
                    text = str(symbol).strip()
                    if text:
                        imported_functions.add(text)
        return imported_functions
