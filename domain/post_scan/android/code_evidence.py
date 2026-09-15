import re
from dataclasses import dataclass
from typing import Any

from domain.post_scan.android.app_component_builder import AppComponentBuilder
from domain.post_scan.android.app_info_builder import AndroidAppInfoBuilder
from domain.post_scan.android.application_builder import ApplicationBuilder
from domain.post_scan.android.hardcoded_values_builder import HardcodedValuesBuilder
from domain.post_scan.utilities import (
    api_call_caller_signature,
    api_call_signature,
    app_package_prefix,
    caller_matches_package,
    coerce_bool_like,
    dedupe_preserve_order,
    first_non_empty,
    matching_api_call_sites,
    matching_string_xrefs,
)


@dataclass
class CodeEvidence:
    accesses_unique_identifiers: dict[str, Any]
    app_is_debuggable: dict[str, Any]
    activities_accessible_to_other_apps: dict[str, Any]
    receivers_accessible_to_other_apps: dict[str, Any]
    services_accessible_to_other_apps: dict[str, Any]
    contains_hard_coded_cryptographic_key: dict[str, Any]
    contains_native_code: dict[str, Any]
    contains_potential_hard_coded_password: dict[str, Any]
    contains_potential_sql_injection: dict[str, Any]
    contains_reflection_code: dict[str, Any]
    creates_blowfish_key_with_weak_length: dict[str, Any]
    creates_rsa_keys_with_weak_modulus_length: dict[str, Any]
    does_not_update_security_provider: dict[str, Any]
    requests_root_access: dict[str, Any]
    cve_2014_8610: dict[str, Any]
    source_code_is_not_obfuscated: dict[str, Any]
    sha1_hashing_algorithm: dict[str, Any]
    weakly_configured_xml_parser: dict[str, Any]
    writes_sensitive_information_to_system_log: dict[str, Any]
    uses_spoofable_values_for_authentication: dict[str, Any]
    copies_sensitive_information_into_clipboard_without_user_consent: dict[str, Any]

    PASSWORD_HINT_PATTERN = re.compile(r"(?i)(?:passw(?:or)?d|passwd|pwd|newpassword|passcode|credential|login|auth)")
    SENSITIVE_LOG_VALUE_PATTERN = re.compile(
        r"(?i)(?:passw(?:or)?d|passwd|pwd|token|secret|session|credential|pin|phonenumber|account)"
    )
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

    def __init__(
        self,
        loaded_outputs: dict[str, Any],
        app_components: AppComponentBuilder,
        application: ApplicationBuilder,
        app_info: AndroidAppInfoBuilder,
    ):
        hardcoded_values = HardcodedValuesBuilder(loaded_outputs)

        aapt2_identity = loaded_outputs.get("aapt2_identity") or {}
        aapt2_permissions = loaded_outputs.get("aapt2_permissions") or {}
        aapt2_posture = loaded_outputs.get("aapt2_manifest_security_posture") or {}
        androguard_api_calls = loaded_outputs.get("androguard_api_calls") or {}
        androguard_findings = loaded_outputs.get("androguard_findings") or {}
        androguard_report_summary = loaded_outputs.get("androguard_report_summary") or {}
        apktool_code_indicators = loaded_outputs.get("apktool_code_indicators") or {}

        api_calls = list(androguard_api_calls.get("items") or [])
        finding_items = list(androguard_findings.get("items") or [])
        code_indicator_items = list(apktool_code_indicators.get("items") or [])
        declared_permissions = {
            first_non_empty(permission.get("name"))
            for permission in aapt2_permissions.get("permissions") or []
            if first_non_empty(permission.get("name"))
        }

        package_prefix = app_package_prefix(loaded_outputs)

        reflection_callers = matching_api_call_sites(
            api_calls,
            lambda item: "reflect" in api_call_signature(item).lower(),
        )
        runtime_exec_callers = matching_api_call_sites(
            api_calls,
            lambda item: "runtime; exec" in api_call_signature(item).lower(),
        )
        provider_update_callers = matching_api_call_sites(
            api_calls,
            lambda item: (
                "providerinstaller" in api_call_caller_signature(item).lower()
                or "providerinstaller" in api_call_signature(item).lower()
            ),
        )

        identifier_callers = matching_api_call_sites(
            api_calls,
            lambda item: any(
                token in api_call_signature(item).lower()
                for token in (
                    "advertisingid",
                    "settings$secure",
                    "android_id",
                    "telephonymanager",
                    "getdeviceid",
                    "getsubscriberid",
                    "getsimserialnumber",
                )
            ),
        )

        sql_callers = matching_api_call_sites(
            api_calls,
            lambda item: any(
                token in api_call_signature(item).lower()
                for token in (
                    "rawquery",
                    "execsql",
                    "sqlitequerybuilder",
                )
            ),
        )

        clipboard_callers = matching_api_call_sites(
            api_calls,
            lambda item: (
                "clipboard" in api_call_signature(item).lower() or "setprimaryclip" in api_call_signature(item).lower()
            ),
        )

        code_indicator_locations = [
            self._format_provenance_location(item.get("provenance") or {}) for item in code_indicator_items
        ]
        report_api_counts = dict(androguard_report_summary.get("api_category_counts") or {})

        password_secret_hits = [
            secret
            for secret in hardcoded_values.secrets
            if self.PASSWORD_HINT_PATTERN.search(f"{secret.get('value', '')} {secret.get('location', '')}")
        ]

        crypto_secret_hits = [
            secret
            for secret in hardcoded_values.secrets
            if any(
                token in f"{secret.get('value', '')} {secret.get('location', '')}".lower()
                for token in ("key", "crypto", "cipher", "aes", "rsa", "des", "blowfish")
            )
        ]

        source_package = first_non_empty(app_info.package_name, aapt2_identity.get("package_name"))
        readable_app_classes = self._readable_app_class_names(
            source_package,
            loaded_outputs,
            runtime_exec_callers,
        )

        native_abis = list(aapt2_identity.get("native_abis") or [])
        native_abi_presence = coerce_bool_like(aapt2_posture.get("native_abi_presence"))

        reflection_present = (
            bool(reflection_callers)
            or any(
                "reflection" in str(finding.get("id", "")).lower()
                or "reflection" in str(finding.get("title", "")).lower()
                for finding in finding_items
            )
            or int(report_api_counts.get("reflection") or 0) > 0
        )

        sql_injection_present = any(
            "sql injection" in str(finding.get("title", "")).lower() for finding in finding_items
        )
        uses_provider_update = bool(provider_update_callers)
        root_access_present = bool(runtime_exec_callers)
        app_debuggable = coerce_bool_like(application.debuggable)
        sms_permission_present = "android.permission.SEND_SMS" in declared_permissions
        accesses_unique_identifiers = bool(identifier_callers)
        source_not_obfuscated = len(readable_app_classes) >= 3
        sha1_evidence = self._detect_sha1_usage(
            loaded_outputs,
            package_prefix,
            api_calls,
            code_indicator_items,
        )
        weak_blowfish_evidence = self._detect_weak_blowfish_key_length(
            loaded_outputs,
            package_prefix,
            api_calls,
            code_indicator_items,
        )
        weak_rsa_evidence = self._detect_weak_rsa_key_length(
            loaded_outputs,
            package_prefix,
            api_calls,
            code_indicator_items,
        )
        weak_xml_evidence = self._detect_weak_xml_parser(
            loaded_outputs,
            package_prefix,
            api_calls,
            code_indicator_items,
        )
        sensitive_log_evidence = self._detect_sensitive_logging(
            loaded_outputs,
            package_prefix,
            api_calls,
        )
        spoofable_auth_evidence = self._detect_spoofable_authentication(
            loaded_outputs,
            package_prefix,
            api_calls,
        )
        self.accesses_unique_identifiers = self.code_evidence_entry(
            present=accesses_unique_identifiers,
            evidence=", ".join(identifier_callers[:5]) if identifier_callers else "no_identifier_api_hits",
            details=identifier_callers[:10],
        )
        self.app_is_debuggable = self.code_evidence_entry(
            present=app_debuggable,
            evidence=f"debuggable={str(app_debuggable).lower()}" if app_debuggable is not None else "",
        )
        self.activities_accessible_to_other_apps = self.component_access_evidence(
            app_components,
            "exported_activities",
            "activities",
        )
        self.contains_hard_coded_cryptographic_key = self.code_evidence_entry(
            present=bool(crypto_secret_hits),
            evidence=", ".join(
                first_non_empty(secret.get("location"), secret.get("value")) for secret in crypto_secret_hits[:5]
            )
            or "no_crypto_key_hits",
            details=crypto_secret_hits[:10],
        )
        self.contains_native_code = self.code_evidence_entry(
            present=bool(native_abis) or native_abi_presence is True,
            evidence=(
                f"native_abis={','.join(native_abis)}"
                if native_abis
                else f"native_abi_presence={str(native_abi_presence).lower()}"
            ),
            details=native_abis,
        )
        self.contains_potential_hard_coded_password = self.code_evidence_entry(
            present=bool(password_secret_hits),
            evidence=", ".join(
                first_non_empty(secret.get("location"), secret.get("value")) for secret in password_secret_hits[:5]
            )
            or "no_password_hits",
            details=password_secret_hits[:10],
        )
        self.contains_potential_sql_injection = self.code_evidence_entry(
            present=sql_injection_present,
            evidence=", ".join(sql_callers[:5]) if sql_injection_present else "no_sql_injection_finding",
            details=sql_callers[:10],
        )
        self.contains_reflection_code = self.code_evidence_entry(
            present=reflection_present,
            evidence=", ".join(
                dedupe_preserve_order(
                    [*reflection_callers[:3], *[loc for loc in code_indicator_locations[:10] if loc]]
                )[:5]
            )
            or f"reflection_count={int(report_api_counts.get('reflection') or 0)}",
            details=reflection_callers[:10],
        )
        self.creates_blowfish_key_with_weak_length = self.code_evidence_entry(
            present=weak_blowfish_evidence.get("present"),
            evidence=weak_blowfish_evidence.get("evidence", ""),
            details=weak_blowfish_evidence.get("details"),
        )
        self.creates_rsa_keys_with_weak_modulus_length = self.code_evidence_entry(
            present=weak_rsa_evidence.get("present"),
            evidence=weak_rsa_evidence.get("evidence", ""),
            details=weak_rsa_evidence.get("details"),
        )
        self.does_not_update_security_provider = self.code_evidence_entry(
            present=not uses_provider_update,
            evidence=(
                ", ".join(provider_update_callers[:5])
                if provider_update_callers
                else "no_security_provider_update_calls"
            ),
            details=provider_update_callers[:10],
        )
        self.activities_accessible_to_other_apps = self.component_access_evidence(
            app_components,
            "exported_activities",
            "activities",
        )
        self.receivers_accessible_to_other_apps = self.component_access_evidence(
            app_components,
            "exported_receivers",
            "receivers",
        )
        self.services_accessible_to_other_apps = self.component_access_evidence(
            app_components,
            "exported_services",
            "services",
        )
        self.requests_root_access = self.code_evidence_entry(
            present=root_access_present,
            evidence=", ".join(runtime_exec_callers[:5]) if runtime_exec_callers else "no_su_runtime_exec_hits",
            details=runtime_exec_callers[:10],
        )
        self.cve_2014_8610 = self.code_evidence_entry(
            present=not sms_permission_present,
            evidence=(
                "android.permission.SEND_SMS missing"
                if not sms_permission_present
                else "android.permission.SEND_SMS declared"
            ),
        )
        self.source_code_is_not_obfuscated = self.code_evidence_entry(
            present=source_not_obfuscated,
            evidence=", ".join(readable_app_classes[:5]) if readable_app_classes else "no_readable_app_class_names",
            details=readable_app_classes[:10],
        )
        self.sha1_hashing_algorithm = self.code_evidence_entry(
            present=sha1_evidence.get("present"),
            evidence=sha1_evidence.get("evidence", ""),
            details=sha1_evidence.get("details"),
        )
        self.weakly_configured_xml_parser = self.code_evidence_entry(
            present=weak_xml_evidence.get("present"),
            evidence=weak_xml_evidence.get("evidence", ""),
            details=weak_xml_evidence.get("details"),
        )
        self.writes_sensitive_information_to_system_log = self.code_evidence_entry(
            present=sensitive_log_evidence.get("present"),
            evidence=sensitive_log_evidence.get("evidence", ""),
            details=sensitive_log_evidence.get("details"),
        )
        self.uses_spoofable_values_for_authentication = self.code_evidence_entry(
            present=spoofable_auth_evidence.get("present"),
            evidence=spoofable_auth_evidence.get("evidence", ""),
            details=spoofable_auth_evidence.get("details"),
        )
        self.copies_sensitive_information_into_clipboard_without_user_consent = self.code_evidence_entry(
            present=bool(clipboard_callers),
            evidence=", ".join(clipboard_callers[:5]) if clipboard_callers else "no_clipboard_hits",
            details=clipboard_callers[:10],
        )

    def code_evidence_entry(
        self,
        *,
        present: bool | None,
        evidence: str,
        details: list[Any] | None = None,
    ) -> dict[str, Any]:
        entry: dict[str, Any] = {
            "present": present,
            "evidence": evidence,
        }
        if details:
            entry["details"] = details
        return entry

    def _detect_sha1_usage(
        self,
        loaded_outputs: dict[str, Any],
        package_prefix: str,
        api_calls: list[dict[str, Any]],
        code_indicator_items: list[dict[str, Any]],
    ) -> dict[str, Any]:
        crypto_callers = matching_api_call_sites(
            api_calls,
            lambda item: (
                caller_matches_package(item, package_prefix)
                and (
                    self._is_hash_api_call(item)
                    or any(
                        token in api_call_signature(item).lower() for token in ("messagedigest", "signature;", "mac;")
                    )
                )
            ),
        )
        sha1_xrefs = matching_string_xrefs(
            loaded_outputs=loaded_outputs,
            value_predicate=lambda value: self.SHA1_PATTERN.search(value) is not None,
            xref_predicate=lambda signature: package_prefix in signature.replace(".", "/") if package_prefix else False,
        )
        locations = self._matching_code_indicator_locations(
            code_indicator_items,
            package_prefix=package_prefix,
            value_predicate=lambda value: self.SHA1_PATTERN.search(value) is not None,
        )
        hits = dedupe_preserve_order(
            [*[caller for caller in crypto_callers if caller in set(sha1_xrefs)], *locations, *sha1_xrefs]
        )
        if hits:
            return {"present": True, "evidence": hits[0], "details": hits[:10]}
        return {
            "present": False,
            "evidence": "no_sha1_hits",
            **({"details": crypto_callers[:10]} if crypto_callers else {}),
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
        main_activity = first_non_empty(aapt2_identity.get("launchable_activity"))
        if main_activity:
            candidates.append(main_activity)

        androguard_components = loaded_outputs.get("androguard_components") or {}
        for component_type in ("activities", "services", "receivers", "providers"):
            for component in androguard_components.get(component_type) or []:
                if not isinstance(component, dict):
                    continue
                candidates.append(first_non_empty(component.get("name"), component.get("class_name")))

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

    def _detect_weak_blowfish_key_length(
        self,
        loaded_outputs: dict[str, Any],
        package_prefix: str,
        api_calls: list[dict[str, Any]],
        code_indicator_items: list[dict[str, Any]],
    ) -> dict[str, Any]:
        crypto_callers = matching_api_call_sites(
            api_calls,
            lambda item: (
                caller_matches_package(item, package_prefix)
                and any(
                    token in api_call_signature(item).lower()
                    for token in ("cipher;", "secretkeyspec", "keygenerator", "secretkeyfactory")
                )
            ),
        )
        blowfish_xrefs = matching_string_xrefs(
            loaded_outputs=loaded_outputs,
            value_predicate=lambda value: self.BLOWFISH_PATTERN.search(value) is not None,
            xref_predicate=lambda signature: package_prefix in signature.replace(".", "/") if package_prefix else False,
        )
        weak_size_xrefs = matching_string_xrefs(
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
        evidence_hits = dedupe_preserve_order([*overlapping, *weak_indicator_locations])
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
        rsa_callers = matching_api_call_sites(
            api_calls,
            lambda item: (
                caller_matches_package(item, package_prefix)
                and any(
                    token in api_call_signature(item).lower()
                    for token in ("keypairgenerator", "rsakeygenparameterspec", "keyfactory", "rsapublickeyspec")
                )
            ),
        )
        rsa_xrefs = matching_string_xrefs(
            loaded_outputs=loaded_outputs,
            value_predicate=lambda value: self.RSA_PATTERN.search(value) is not None,
            xref_predicate=lambda signature: package_prefix in signature.replace(".", "/") if package_prefix else False,
        )
        weak_size_xrefs = matching_string_xrefs(
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
        evidence_hits = dedupe_preserve_order([*overlapping, *weak_indicator_locations])
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
        parser_callers = matching_api_call_sites(
            api_calls,
            lambda item: (
                caller_matches_package(item, package_prefix)
                and self.XML_PARSER_PATTERN.search(api_call_signature(item)) is not None
            ),
        )
        weak_xrefs = matching_string_xrefs(
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
        evidence_hits = dedupe_preserve_order([*overlapping, *weak_indicator_locations, *weak_xrefs])
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
        log_callers = matching_api_call_sites(
            api_calls,
            lambda item: (
                caller_matches_package(item, package_prefix) and "android/util/log" in api_call_signature(item).lower()
            ),
        )
        if not log_callers:
            return {"present": False, "evidence": "no_sensitive_logging_hits"}

        sensitive_xrefs = matching_string_xrefs(
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
        identifier_callers = matching_api_call_sites(
            api_calls,
            lambda item: (
                caller_matches_package(item, package_prefix)
                and self.SPOOFABLE_IDENTIFIER_PATTERN.search(api_call_signature(item)) is not None
            ),
        )
        auth_xrefs = matching_string_xrefs(
            loaded_outputs=loaded_outputs,
            value_predicate=lambda value: self.AUTH_VALUE_PATTERN.search(value) is not None,
            xref_predicate=lambda signature: package_prefix in signature.replace(".", "/") if package_prefix else False,
        )
        network_callers = matching_api_call_sites(
            api_calls,
            lambda item: caller_matches_package(item, package_prefix) and self._is_network_api_call(item),
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
            value = first_non_empty(item.get("value"))
            if not value or not value_predicate(value):
                continue
            provenance = item.get("provenance") or {}
            path = first_non_empty(provenance.get("path"), provenance.get("source"))
            normalized_path = path.replace(".", "/")
            if normalized_package and normalized_package not in normalized_path:
                continue
            location = self._format_provenance_location(provenance)
            if location:
                matches.append(location)
        return dedupe_preserve_order(matches)

    def _is_network_api_call(self, item: dict[str, Any]) -> bool:
        categories = {str(category).strip().lower() for category in (item.get("categories") or [])}
        if "network" in categories:
            return True
        return any(hint in api_call_signature(item).lower() for hint in self.NETWORK_API_HINTS)

    def _is_hash_api_call(self, item: dict[str, Any]) -> bool:
        categories = {str(category).strip().lower() for category in (item.get("categories") or [])}
        if "crypto" in categories:
            return True
        signature = api_call_signature(item).lower()
        method_name = first_non_empty((item.get("callee") or {}).get("method_name")).lower()
        if any(hint in signature for hint in self.HASH_API_HINTS):
            return True
        return method_name in {"digest", "dofinal"}

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

    @staticmethod
    def _format_provenance_location(provenance: dict[str, Any]) -> str:
        path = str(provenance.get("path", "")).strip()
        line = provenance.get("line")
        if path and line not in (None, ""):
            return f"{path}:{line}"
        return path

    def component_access_evidence(
        self,
        app_components: AppComponentBuilder,
        exported_key: str,
        label: str,
    ) -> dict[str, Any]:
        exported_count = int(getattr(app_components, exported_key, 0) or 0)
        return self.code_evidence_entry(
            present=exported_count > 0,
            evidence=f"{exported_key}={exported_count}",
            details=[f"{label}={int(getattr(app_components, label, 0) or 0)}"],
        )
