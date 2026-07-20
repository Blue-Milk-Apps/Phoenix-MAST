from dataclasses import dataclass
from typing import Any

from domain.post_scan.android.app_component_builder import AppComponentBuilder
from domain.post_scan.android.app_info_builder import AndroidAppInfoBuilder
from domain.post_scan.android.application_builder import ApplicationBuilder
from domain.post_scan.utilities import build_hardcoded_values, matching_api_call_sites


@dataclass
class CodeEvidenceBuilder:
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

    def __init__(
        self,
        loaded_outputs: dict[str:Any],
        app_components: AppComponentBuilder,
        application: ApplicationBuilder,
        app_info: AndroidAppInfoBuilder,
    ):
        hardcoded_values = build_hardcoded_values(self, loaded_outputs)

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
            self._first_non_empty(permission.get("name"))
            for permission in aapt2_permissions.get("permissions") or []
            if self._first_non_empty(permission.get("name"))
        }

        package_prefix = self._app_package_prefix(loaded_outputs)

        reflection_callers = matching_api_call_sites(
            self,
            api_calls,
            lambda item: "reflect" in self._api_call_signature(item).lower(),
        )
        runtime_exec_callers = matching_api_call_sites(
            self,
            api_calls,
            lambda item: "runtime; exec" in self._api_call_signature(item).lower(),
        )
        provider_update_callers = matching_api_call_sites(
            self,
            api_calls,
            lambda item: (
                "providerinstaller" in self._api_call_caller_signature(item).lower()
                or "providerinstaller" in self._api_call_signature(item).lower()
            ),
        )

        identifier_callers = matching_api_call_sites(
            self,
            api_calls,
            lambda item: any(
                token in self._api_call_signature(item).lower()
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
            self,
            api_calls,
            lambda item: any(
                token in self._api_call_signature(item).lower()
                for token in (
                    "rawquery",
                    "execsql",
                    "sqlitequerybuilder",
                )
            ),
        )

        clipboard_callers = matching_api_call_sites(
            self,
            api_calls,
            lambda item: (
                "clipboard" in self._api_call_signature(item).lower()
                or "setprimaryclip" in self._api_call_signature(item).lower()
            ),
        )

        code_indicator_locations = [
            self._format_provenance_location(item.get("provenance") or {}) for item in code_indicator_items
        ]
        report_api_counts = dict(androguard_report_summary.get("api_category_counts") or {})

        password_secret_hits = [
            secret
            for secret in hardcoded_values.get("secrets") or []
            if self.PASSWORD_HINT_PATTERN.search(f"{secret.get('value', '')} {secret.get('location', '')}")
        ]

        crypto_secret_hits = [
            secret
            for secret in hardcoded_values.get("secrets") or []
            if any(
                token in f"{secret.get('value', '')} {secret.get('location', '')}".lower()
                for token in ("key", "crypto", "cipher", "aes", "rsa", "des", "blowfish")
            )
        ]

        source_package = self._first_non_empty(app_info.package_name, aapt2_identity.get("package_name"))
        readable_app_classes = self._readable_app_class_names(
            source_package,
            loaded_outputs,
            runtime_exec_callers,
        )

        native_abis = list(aapt2_identity.get("native_abis") or [])
        native_abi_presence = self._coerce_bool_like(aapt2_posture.get("native_abi_presence"))

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
        app_debuggable = self._coerce_bool_like(application.debuggable)
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
                self._first_non_empty(secret.get("location"), secret.get("value")) for secret in crypto_secret_hits[:5]
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
                self._first_non_empty(secret.get("location"), secret.get("value"))
                for secret in password_secret_hits[:5]
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
                self._dedupe_preserve_order(
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

    def __getattr__(self, name: str) -> Any:
        """Delegate unmigrated evidence helpers until they move into domain utilities."""
        if not (name.startswith("_") or name.isupper()):
            raise AttributeError(name)

        from adapters.post_scan.android_binary_scan_detail_extractor import AndroidBinaryScanDetailExtractor

        helper = getattr(AndroidBinaryScanDetailExtractor(), name, None)
        if helper is None:
            raise AttributeError(name)
        return helper
