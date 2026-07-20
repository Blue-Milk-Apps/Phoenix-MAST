"""Android binary detail extractor for post-scan processing."""

from __future__ import annotations

import re
from dataclasses import asdict
from typing import Any

from domain.post_scan.android.app_certificate_builder import AppCertificateBuilder
from domain.post_scan.android.app_component_builder import AppComponentBuilder
from domain.post_scan.android.app_info_builder import AndroidAppInfoBuilder
from domain.post_scan.android.application_builder import ApplicationBuilder
from domain.post_scan.android.code_evidence_builder import CodeEvidenceBuilder
from domain.post_scan.android.deep_links_builder import DeepLinksBuilder
from domain.post_scan.android.endpoints_builder import EndpointsBuilder
from domain.post_scan.android.file_info_builder import FileInfoBuilder
from domain.post_scan.android.functionality_builder import FunctionalityBuilder
from domain.post_scan.android.hardcoded_values_builder import HardcodedValuesBuilder
from domain.post_scan.android.network_evidence_builder import NetworkEvidenceBuilder
from domain.post_scan.android.permissions_builder import PermissionsBuilder
from domain.post_scan.android.resilience_evidence_builder import ResilienceEvidenceBuilder
from domain.post_scan.android.storage_evidence_builder import StorageEvidenceBuilder
from ports.scan_detail_extractor_port import ScanDetailExtractorPort


class AndroidBinaryScanDetailExtractor(ScanDetailExtractorPort):
    """Extract Android-binary-specific sections from loaded scan outputs."""

    ENCODED_SECRET_PATTERN = re.compile(r"(?<![A-Za-z0-9+/=])[A-Za-z0-9+/]{40,}={0,2}(?![A-Za-z0-9+/=])")
    JVM_DESCRIPTOR_PATTERN = re.compile(r"^\+?L(?:[A-Za-z0-9_$]+/)+[A-Za-z0-9_$]+$")
    SECRET_LABEL_PATTERN = re.compile(
        r"(?i)^(?:api[_-]?key|client[_-]?secret|secret[_-]?key|access[_-]?token|secretkey)$"
    )
    ROOT_DETECTION_PATTERN = re.compile(r"(?i)(?:\bsu\b|busybox|supersu|magisk|test-keys|rootbeer|isrooted|rootcheck)")

    def extract_sections(self, loaded_outputs: dict[str, Any]) -> dict[str, Any]:
        app_info = AndroidAppInfoBuilder(loaded_outputs)
        application = ApplicationBuilder(loaded_outputs)
        app_components = AppComponentBuilder(loaded_outputs)
        certificate = AppCertificateBuilder(loaded_outputs)
        code_evidence = CodeEvidenceBuilder(loaded_outputs, app_components, application, app_info)
        file_info = FileInfoBuilder(loaded_outputs)
        permissions = PermissionsBuilder(loaded_outputs).items
        functionality = FunctionalityBuilder(loaded_outputs).items
        resilience_evidence = ResilienceEvidenceBuilder(loaded_outputs)
        deeplink_builder = DeepLinksBuilder(loaded_outputs)
        hardcoded_values = HardcodedValuesBuilder(loaded_outputs)
        network_evidence = NetworkEvidenceBuilder(loaded_outputs, hardcoded_values)
        storage_evidence = StorageEvidenceBuilder(loaded_outputs, hardcoded_values)
        endpoints = EndpointsBuilder(loaded_outputs).items

        return {
            "app_info": asdict(app_info),
            "application": asdict(application),
            "app_components": asdict(app_components),
            "certificate": asdict(certificate),
            "code_evidence": asdict(code_evidence),
            "file_info": asdict(file_info),
            "permissions": permissions,
            "functionality": functionality,
            "network_evidence": asdict(network_evidence),
            "resilience_evidence": asdict(resilience_evidence),
            "storage_evidence": asdict(storage_evidence),
            "deep_links": asdict(deeplink_builder),
            "hardcoded_values": asdict(hardcoded_values),
            "endpoints": endpoints,
        }

    def _summarize_code_indicators(self, artifact: dict[str, Any]) -> dict[str, Any]:
        items = artifact.get("items") or []
        category_counts: dict[str, int] = {}
        sample_values_by_category: dict[str, list[str]] = {}
        sample_locations_by_category: dict[str, list[str]] = {}

        for item in items:
            if not isinstance(item, dict):
                continue
            category = self._first_non_empty((item.get("context") or {}).get("category")) or "uncategorized"
            category_counts[category] = category_counts.get(category, 0) + 1

            value = self._first_non_empty(item.get("value"))
            if value:
                sample_values_by_category.setdefault(category, [])
                if value not in sample_values_by_category[category] and len(sample_values_by_category[category]) < 5:
                    sample_values_by_category[category].append(value)

            location = self._format_provenance_location(item.get("provenance") or {})
            if location:
                sample_locations_by_category.setdefault(category, [])
                if (
                    location not in sample_locations_by_category[category]
                    and len(sample_locations_by_category[category]) < 5
                ):
                    sample_locations_by_category[category].append(location)

        return {
            "item_count": len(items),
            "category_counts": category_counts,
            "sample_values_by_category": sample_values_by_category,
            "sample_locations_by_category": sample_locations_by_category,
        }

    def _summarize_findings(self, artifact: dict[str, Any]) -> dict[str, Any]:
        items = artifact.get("items") or []
        severity_counts: dict[str, int] = {}
        finding_ids: list[str] = []
        finding_titles: list[str] = []
        findings: list[dict[str, Any]] = []

        for item in items:
            if not isinstance(item, dict):
                continue

            severity = self._first_non_empty(item.get("severity")).lower()
            if severity:
                severity_counts[severity] = severity_counts.get(severity, 0) + 1

            finding_id = self._first_non_empty(item.get("id"))
            title = self._first_non_empty(item.get("title"))
            if finding_id and finding_id not in finding_ids:
                finding_ids.append(finding_id)
            if title and title not in finding_titles:
                finding_titles.append(title)

            evidence_callers: list[str] = []
            for evidence_item in item.get("evidence") or []:
                if not isinstance(evidence_item, dict):
                    continue
                caller_signature = self._first_non_empty(((evidence_item.get("caller") or {}).get("signature")))
                if caller_signature and caller_signature not in evidence_callers and len(evidence_callers) < 5:
                    evidence_callers.append(caller_signature)

            findings.append(
                {
                    "id": finding_id,
                    "title": title,
                    "severity": severity,
                    "confidence": self._first_non_empty(item.get("confidence")),
                    "sample_callers": evidence_callers,
                }
            )

        return {
            "item_count": len(items),
            "severity_counts": severity_counts,
            "finding_ids": finding_ids,
            "finding_titles": finding_titles,
            "findings": findings,
        }

    def _summarize_strings(self, artifact: dict[str, Any]) -> dict[str, Any]:
        items = artifact.get("items") or []
        category_counts: dict[str, int] = {}
        sample_values_by_category: dict[str, list[str]] = {}
        sample_xrefs_by_category: dict[str, list[str]] = {}

        for item in items:
            if not isinstance(item, dict):
                continue
            categories = [str(category).strip() for category in (item.get("categories") or []) if str(category).strip()]
            value = self._first_non_empty(item.get("value"))
            xrefs = item.get("xrefs") or []

            for category in categories or ["uncategorized"]:
                category_counts[category] = category_counts.get(category, 0) + 1
                if value:
                    sample_values_by_category.setdefault(category, [])
                    if (
                        value not in sample_values_by_category[category]
                        and len(sample_values_by_category[category]) < 5
                    ):
                        sample_values_by_category[category].append(value)

                for xref in xrefs:
                    if not isinstance(xref, dict):
                        continue
                    signature = self._first_non_empty(xref.get("signature"))
                    if not signature:
                        continue
                    sample_xrefs_by_category.setdefault(category, [])
                    if (
                        signature not in sample_xrefs_by_category[category]
                        and len(sample_xrefs_by_category[category]) < 5
                    ):
                        sample_xrefs_by_category[category].append(signature)

        return {
            "item_count": len(items),
            "category_counts": category_counts,
            "sample_values_by_category": sample_values_by_category,
            "sample_xrefs_by_category": sample_xrefs_by_category,
        }

    def _looks_like_encoded_secret(self, value: str) -> bool:
        if len(value) < 40:
            return False
        if len(value) % 4 not in {0, 2, 3}:
            return False
        if self.JVM_DESCRIPTOR_PATTERN.fullmatch(value):
            return False
        if not any(char in value for char in "+="):
            return False
        return len(set(value)) >= 10

    def _looks_like_secret_label(self, value: str) -> bool:
        return self.SECRET_LABEL_PATTERN.fullmatch(value.strip()) is not None

    @staticmethod
    def _primary_certificate(
        androguard_certificates: dict[str, Any],
        apksigner_signing_evidence: dict[str, Any],
    ) -> dict[str, Any]:
        all_certs = androguard_certificates.get("all") or []
        if all_certs:
            return all_certs[0]

        signer_certs = apksigner_signing_evidence.get("signers") or []
        if signer_certs:
            return signer_certs[0].get("certificate") or {}

        return {}

    @staticmethod
    def _format_validity(not_before: object, not_after: object) -> str:
        start = str(not_before or "").strip()
        end = str(not_after or "").strip()
        if start and end:
            return f"{start} to {end}"
        return start or end

    @staticmethod
    def _format_identity(identity: dict[str, Any]) -> str:
        parts = [
            str(identity.get("common_name", "")).strip(),
            str(identity.get("organization_name", "")).strip(),
            str(identity.get("organizational_unit_name", "")).strip(),
        ]
        return ", ".join(part for part in parts if part)

    @staticmethod
    def _format_hash_algorithms(primary_certificate: dict[str, Any], apksigner_signing_evidence: dict[str, Any]) -> str:
        values: list[str] = []

        if primary_certificate.get("sha1"):
            values.append("SHA1")
        if primary_certificate.get("sha256"):
            values.append("SHA256")

        signer_cert = ((apksigner_signing_evidence.get("signers") or [{}])[0]).get("certificate") or {}
        signature_algorithm = str(signer_cert.get("signature_algorithm", "")).strip()
        if signature_algorithm and signature_algorithm.upper() != "UNKNOWN":
            values.append(signature_algorithm)

        public_key_algorithm = str(signer_cert.get("public_key_algorithm", "")).strip()
        if public_key_algorithm:
            values.append(public_key_algorithm)

        deduped: list[str] = []
        for value in values:
            if value not in deduped:
                deduped.append(value)
        return ", ".join(deduped)

    @staticmethod
    def _extract_dn_value(distinguished_name: object, key: str) -> str:
        text = str(distinguished_name or "").strip()
        if not text:
            return ""

        for part in text.split(","):
            cleaned = part.strip()
            prefix = f"{key}="
            if cleaned.startswith(prefix):
                return cleaned[len(prefix) :].strip()
        return ""

    @staticmethod
    def _first_non_empty(*values: object) -> str:
        for value in values:
            if value is None:
                continue
            text = str(value).strip()
            if text:
                return text
        return ""

    @staticmethod
    def _looks_like_email(value: str) -> bool:
        if "@" not in value:
            return False
        local_part, _, domain_part = value.partition("@")
        return bool(local_part and "." in domain_part)

    @staticmethod
    def _format_provenance_location(provenance: dict[str, Any]) -> str:
        path = str(provenance.get("path", "")).strip()
        line = provenance.get("line")
        if path and line not in (None, ""):
            return f"{path}:{line}"
        return path
