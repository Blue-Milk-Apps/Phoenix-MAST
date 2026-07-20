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
    PASSWORD_HINT_PATTERN = re.compile(r"(?i)(?:passw(?:or)?d|passwd|pwd|newpassword|passcode|credential|login|auth)")
    SENSITIVE_LOG_VALUE_PATTERN = re.compile(
        r"(?i)(?:passw(?:or)?d|passwd|pwd|token|secret|session|credential|pin|phonenumber|account)"
    )
    ROOT_DETECTION_PATTERN = re.compile(r"(?i)(?:\bsu\b|busybox|supersu|magisk|test-keys|rootbeer|isrooted|rootcheck)")
    SHA1_PATTERN = re.compile(r"(?i)\bsha(?:-|_)?1(?:withrsa)?\b")
    BLOWFISH_PATTERN = re.compile(r"(?i)\bblowfish\b")
    WEAK_BLOWFISH_KEY_BITS_PATTERN = re.compile(r"\b(?:32|40|56|64|96|112|120)\b")
    RSA_PATTERN = re.compile(r"(?i)\brsa\b")
    WEAK_RSA_KEY_BITS_PATTERN = re.compile(r"\b(?:256|384|512|768)\b")
    XML_PARSER_PATTERN = re.compile(r"(?i)(?:xmlpullparser|saxparserfactory|documentbuilderfactory|xmlreader)")
    WEAK_XML_PATTERN = re.compile(
        r"(?i)(?:external-general-entities|external-parameter-entities|load-external-dtd|disallow-doctype-decl|resolveentity|setfeature)"
    )
    AUTH_VALUE_PATTERN = re.compile(r"(?i)(?:auth|login|token|password|session|credential)")
    SPOOFABLE_IDENTIFIER_PATTERN = re.compile(
        r"(?i)(?:android_id|advertisingid|deviceid|getdeviceid|getsubscriberid|getsimserialnumber|telephonymanager)"
    )
    NETWORK_API_HINTS = (
        "httpurlconnection",
        "httpsurlconnection",
        "okhttp",
        "retrofit",
        "org/apache/http",
        "httpclient",
        "socket",
        "url; openconnection",
        "webview",
        "posturl",
        "loadurl",
    )
    HASH_API_HINTS = (
        "messagedigest",
        "digest",
        "java/security/mac",
        "mac; dofinal",
        "secretkeyfactory",
        "pbkdf",
        "bcrypt",
        "scrypt",
        "argon2",
    )

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

    def _readable_app_class_names(
        self,
        package_name: str,
        loaded_outputs: dict[str, Any],
        runtime_exec_callers: list[str],
    ) -> list[str]:
        candidates: list[str] = []
        package_prefix = package_name.replace(".", "/")
        if not package_prefix:
            return []

        aapt2_identity = loaded_outputs.get("aapt2_identity") or {}
        main_activity = self._first_non_empty(aapt2_identity.get("launchable_activity"))
        if main_activity:
            candidates.append(main_activity)

        androguard_components = loaded_outputs.get("androguard_components") or {}
        for component_type in ("activities", "services", "receivers", "providers"):
            for component in androguard_components.get(component_type) or []:
                if not isinstance(component, dict):
                    continue
                candidates.append(
                    self._first_non_empty(
                        component.get("name"),
                        component.get("class_name"),
                    )
                )

        candidates.extend(runtime_exec_callers)

        readable: list[str] = []
        for candidate in candidates:
            text = str(candidate or "").strip()
            if not text:
                continue
            normalized = text.replace(".", "/")
            if package_prefix not in normalized:
                continue
            simple_name = normalized.rsplit("/", 1)[-1].split(";")[0]
            if self._looks_readable_class_name(simple_name) and simple_name not in readable:
                readable.append(simple_name)
        return readable

    @staticmethod
    def _looks_readable_class_name(value: str) -> bool:
        text = str(value or "").strip("$;")
        if len(text) < 4:
            return False
        if text.lower() == text or text.upper() == text:
            return False
        letters_only = "".join(char for char in text if char.isalpha())
        if len(letters_only) < 4:
            return False
        return sum(char.lower() in "aeiou" for char in letters_only.lower()) >= 2

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

    def _detect_weak_blowfish_key_length(
        self,
        loaded_outputs: dict[str, Any],
        package_prefix: str,
        api_calls: list[dict[str, Any]],
        code_indicator_items: list[dict[str, Any]],
    ) -> dict[str, Any]:
        crypto_callers = self._matching_api_call_sites(
            api_calls,
            lambda item: (
                self._caller_matches_package(item, package_prefix)
                and any(
                    token in self._api_call_signature(item).lower()
                    for token in ("cipher;", "secretkeyspec", "keygenerator", "secretkeyfactory")
                )
            ),
        )
        blowfish_xrefs = self._matching_string_xrefs(
            loaded_outputs=loaded_outputs,
            value_predicate=lambda value: self.BLOWFISH_PATTERN.search(value) is not None,
            xref_predicate=lambda signature: package_prefix in signature.replace(".", "/") if package_prefix else False,
        )
        weak_size_xrefs = self._matching_string_xrefs(
            loaded_outputs=loaded_outputs,
            value_predicate=lambda value: self.WEAK_BLOWFISH_KEY_BITS_PATTERN.search(value) is not None,
            xref_predicate=lambda signature: package_prefix in signature.replace(".", "/") if package_prefix else False,
        )
        weak_indicator_locations = self._matching_code_indicator_locations(
            code_indicator_items,
            package_prefix=package_prefix,
            value_predicate=lambda value: (
                self.BLOWFISH_PATTERN.search(value) is not None
                and self.WEAK_BLOWFISH_KEY_BITS_PATTERN.search(value) is not None
            ),
        )
        overlapping = [
            caller for caller in crypto_callers if caller in set(blowfish_xrefs) and caller in set(weak_size_xrefs)
        ]
        evidence_hits = self._dedupe_preserve_order([*overlapping, *weak_indicator_locations])
        if evidence_hits:
            return {"present": True, "evidence": evidence_hits[0], "details": evidence_hits[:10]}
        if crypto_callers or blowfish_xrefs:
            return {"present": False, "evidence": "no_blowfish_weak_key_hits"}
        return {"present": False, "evidence": "no_blowfish_weak_key_hits"}

    def _detect_weak_rsa_key_length(
        self,
        loaded_outputs: dict[str, Any],
        package_prefix: str,
        api_calls: list[dict[str, Any]],
        code_indicator_items: list[dict[str, Any]],
    ) -> dict[str, Any]:
        rsa_callers = self._matching_api_call_sites(
            api_calls,
            lambda item: (
                self._caller_matches_package(item, package_prefix)
                and any(
                    token in self._api_call_signature(item).lower()
                    for token in ("keypairgenerator", "rsakeygenparameterspec", "keyfactory", "rsapublickeyspec")
                )
            ),
        )
        rsa_xrefs = self._matching_string_xrefs(
            loaded_outputs=loaded_outputs,
            value_predicate=lambda value: self.RSA_PATTERN.search(value) is not None,
            xref_predicate=lambda signature: package_prefix in signature.replace(".", "/") if package_prefix else False,
        )
        weak_size_xrefs = self._matching_string_xrefs(
            loaded_outputs=loaded_outputs,
            value_predicate=lambda value: self.WEAK_RSA_KEY_BITS_PATTERN.search(value) is not None,
            xref_predicate=lambda signature: package_prefix in signature.replace(".", "/") if package_prefix else False,
        )
        weak_indicator_locations = self._matching_code_indicator_locations(
            code_indicator_items,
            package_prefix=package_prefix,
            value_predicate=lambda value: (
                self.RSA_PATTERN.search(value) is not None and self.WEAK_RSA_KEY_BITS_PATTERN.search(value) is not None
            ),
        )
        overlapping = [caller for caller in rsa_callers if caller in set(rsa_xrefs) and caller in set(weak_size_xrefs)]
        evidence_hits = self._dedupe_preserve_order([*overlapping, *weak_indicator_locations])
        if evidence_hits:
            return {"present": True, "evidence": evidence_hits[0], "details": evidence_hits[:10]}
        if rsa_callers or rsa_xrefs:
            return {"present": False, "evidence": "no_weak_rsa_key_length_hits"}
        return {"present": False, "evidence": "no_weak_rsa_key_length_hits"}

    def _detect_weak_xml_parser(
        self,
        loaded_outputs: dict[str, Any],
        package_prefix: str,
        api_calls: list[dict[str, Any]],
        code_indicator_items: list[dict[str, Any]],
    ) -> dict[str, Any]:
        parser_callers = self._matching_api_call_sites(
            api_calls,
            lambda item: (
                self._caller_matches_package(item, package_prefix)
                and self.XML_PARSER_PATTERN.search(self._api_call_signature(item)) is not None
            ),
        )
        weak_xrefs = self._matching_string_xrefs(
            loaded_outputs=loaded_outputs,
            value_predicate=lambda value: self.WEAK_XML_PATTERN.search(value) is not None,
            xref_predicate=lambda signature: package_prefix in signature.replace(".", "/") if package_prefix else False,
        )
        weak_indicator_locations = self._matching_code_indicator_locations(
            code_indicator_items,
            package_prefix=package_prefix,
            value_predicate=lambda value: self.WEAK_XML_PATTERN.search(value) is not None,
        )
        overlapping = [caller for caller in parser_callers if caller in set(weak_xrefs)]
        evidence_hits = self._dedupe_preserve_order([*overlapping, *weak_indicator_locations, *weak_xrefs])
        if evidence_hits:
            return {"present": True, "evidence": evidence_hits[0], "details": evidence_hits[:10]}
        if parser_callers:
            return {"present": False, "evidence": "no_weak_xml_parser_hits", "details": parser_callers[:10]}
        return {"present": False, "evidence": "no_weak_xml_parser_hits"}

    def _detect_sensitive_logging(
        self,
        loaded_outputs: dict[str, Any],
        package_prefix: str,
        api_calls: list[dict[str, Any]],
    ) -> dict[str, Any]:
        log_callers = self._matching_api_call_sites(
            api_calls,
            lambda item: (
                self._caller_matches_package(item, package_prefix)
                and "android/util/log" in self._api_call_signature(item).lower()
            ),
        )
        if not log_callers:
            return {"present": False, "evidence": "no_sensitive_logging_hits"}

        sensitive_xrefs = self._matching_string_xrefs(
            loaded_outputs=loaded_outputs,
            value_predicate=lambda value: self.SENSITIVE_LOG_VALUE_PATTERN.search(value) is not None,
            xref_predicate=lambda signature: package_prefix in signature.replace(".", "/") if package_prefix else False,
        )
        overlapping = [caller for caller in log_callers if caller in set(sensitive_xrefs)]
        if overlapping:
            return {"present": True, "evidence": overlapping[0], "details": overlapping[:10]}
        return {"present": False, "evidence": "no_sensitive_logging_hits", "details": log_callers[:10]}

    def _detect_spoofable_authentication(
        self,
        loaded_outputs: dict[str, Any],
        package_prefix: str,
        api_calls: list[dict[str, Any]],
    ) -> dict[str, Any]:
        identifier_callers = self._matching_api_call_sites(
            api_calls,
            lambda item: (
                self._caller_matches_package(item, package_prefix)
                and self.SPOOFABLE_IDENTIFIER_PATTERN.search(self._api_call_signature(item)) is not None
            ),
        )
        auth_xrefs = self._matching_string_xrefs(
            loaded_outputs=loaded_outputs,
            value_predicate=lambda value: self.AUTH_VALUE_PATTERN.search(value) is not None,
            xref_predicate=lambda signature: package_prefix in signature.replace(".", "/") if package_prefix else False,
        )
        network_callers = self._matching_api_call_sites(
            api_calls,
            lambda item: self._caller_matches_package(item, package_prefix) and self._is_network_api_call(item),
        )

        overlapping = [
            caller for caller in identifier_callers if caller in set(auth_xrefs) or caller in set(network_callers)
        ]
        if overlapping:
            return {"present": True, "evidence": overlapping[0], "details": overlapping[:10]}
        if identifier_callers:
            return {
                "present": False,
                "evidence": "no_spoofable_authentication_hits",
                "details": identifier_callers[:10],
            }
        return {"present": False, "evidence": "no_spoofable_authentication_hits"}

    def _api_call_method_name(self, item: dict[str, Any]) -> str:
        callee = item.get("callee") or {}
        return self._first_non_empty(callee.get("method_name"))

    def _matching_api_call_sites(
        self,
        api_calls: list[dict[str, Any]],
        predicate: Any,
    ) -> list[str]:
        callers: list[str] = []
        for item in api_calls:
            if not isinstance(item, dict) or not predicate(item):
                continue
            signature = self._first_non_empty(((item.get("caller") or {}).get("signature")))
            if signature:
                callers.append(signature)
        return self._dedupe_preserve_order(callers)

    def _api_call_signature(self, item: dict[str, Any]) -> str:
        callee = item.get("callee") or {}
        return self._first_non_empty(
            callee.get("signature"),
            callee.get("class_name"),
            callee.get("method_name"),
        )

    def _api_call_caller_signature(self, item: dict[str, Any]) -> str:
        caller = item.get("caller") or {}
        return self._first_non_empty(
            caller.get("signature"),
            caller.get("class_name"),
            caller.get("method_name"),
        )

    def _caller_matches_package(self, item: dict[str, Any], package_prefix: str) -> bool:
        if not package_prefix:
            return False
        caller_signature = self._api_call_caller_signature(item)
        return package_prefix in caller_signature.replace(".", "/")

    def _matching_code_indicator_locations(
        self,
        code_indicator_items: list[dict[str, Any]],
        *,
        package_prefix: str,
        value_predicate: Any,
    ) -> list[str]:
        matches: list[str] = []
        normalized_package = package_prefix.replace(".", "/")
        for item in code_indicator_items:
            if not isinstance(item, dict):
                continue
            value = self._first_non_empty(item.get("value"))
            if not value or not value_predicate(value):
                continue
            provenance = item.get("provenance") or {}
            path = self._first_non_empty(provenance.get("path"), provenance.get("source"))
            normalized_path = path.replace(".", "/")
            if normalized_package and normalized_package not in normalized_path:
                continue
            location = self._format_provenance_location(provenance)
            if location:
                matches.append(location)
        return self._dedupe_preserve_order(matches)

    def _matching_string_xrefs(
        self,
        *,
        loaded_outputs: dict[str, Any],
        value_predicate: Any,
        xref_predicate: Any,
    ) -> list[str]:
        androguard_strings = loaded_outputs.get("androguard_strings") or {}
        matches: list[str] = []
        for item in androguard_strings.get("items") or []:
            if not isinstance(item, dict):
                continue
            value = self._first_non_empty(item.get("value"))
            if not value or not value_predicate(value):
                continue
            for xref in item.get("xrefs") or []:
                if not isinstance(xref, dict):
                    continue
                signature = self._first_non_empty(xref.get("signature"))
                if signature and xref_predicate(signature):
                    matches.append(signature)
        return self._dedupe_preserve_order(matches)

    def _app_package_prefix(self, loaded_outputs: dict[str, Any]) -> str:
        return self._first_non_empty(
            ((loaded_outputs.get("aapt2_identity") or {}).get("package_name")),
            ((loaded_outputs.get("androguard_metadata") or {}).get("package")),
        ).replace(".", "/")

    def _is_network_api_call(self, item: dict[str, Any]) -> bool:
        categories = {str(category).strip().lower() for category in (item.get("categories") or [])}
        if "network" in categories:
            return True
        signature = self._api_call_signature(item).lower()
        return any(hint in signature for hint in self.NETWORK_API_HINTS)

    def _is_hash_api_call(self, item: dict[str, Any]) -> bool:
        categories = {str(category).strip().lower() for category in (item.get("categories") or [])}
        if "crypto" in categories:
            return True
        signature = self._api_call_signature(item).lower()
        method_name = self._api_call_method_name(item).lower()
        if any(hint in signature for hint in self.HASH_API_HINTS):
            return True
        return method_name in {"digest", "dofinal"}

    @staticmethod
    def _dedupe_preserve_order(values: list[str]) -> list[str]:
        seen: set[str] = set()
        deduped: list[str] = []
        for value in values:
            if not value or value in seen:
                continue
            seen.add(value)
            deduped.append(value)
        return deduped
