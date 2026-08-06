"""Build Android network evidence."""

import re
from dataclasses import dataclass
from typing import Any

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
class NetworkEvidence:
    allows_cleartext_traffic_for_all_domains: dict[str, Any]
    contains_hostname_verifier_accepts_all: dict[str, Any]
    contains_x509_trust_manager_accepts_all: dict[str, Any]
    does_not_perform_certificate_pinning: dict[str, Any]
    opens_listening_port: dict[str, Any]
    sensitive_cookies_lack_security_attributes: dict[str, Any]
    unnecessary_information_transmitted: dict[str, Any]
    sensitive_information_unencrypted_in_transit: dict[str, Any]
    password_not_hashed_in_transit: dict[str, Any]
    weak_certificate_validation_enables_mitm: dict[str, Any]
    manifest_cleartext_traffic_permitted: bool | None

    COOKIE_PATTERN = re.compile(r"(?i)\bcookie\b")
    COOKIE_SECURITY_ATTR_PATTERN = re.compile(r"(?i)\b(?:secure|httponly|samesite)\b")
    PASSWORD_HINT_PATTERN = re.compile(r"(?i)(?:passw(?:or)?d|passwd|pwd|newpassword|passcode|credential|login|auth)")
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

    def __init__(self, loaded_outputs: dict[str, Any], hardcoded_values: HardcodedValuesBuilder) -> None:
        network_security = loaded_outputs.get("apktool_network_security_config") or {}
        aapt2_application = loaded_outputs.get("aapt2_application") or {}
        aapt2_posture = loaded_outputs.get("aapt2_manifest_security_posture") or {}
        androguard_api_calls = loaded_outputs.get("androguard_api_calls") or {}
        package_prefix = app_package_prefix(loaded_outputs)

        domains = network_security.get("domains") or []
        provenance = network_security.get("provenance") or {}
        provenance_path = first_non_empty(provenance.get("path"), provenance.get("source"))
        cleartext_present = self._coerce_true(
            network_security.get("effective_cleartext_traffic_default")
        ) or self._coerce_true(network_security.get("manifest_uses_cleartext_traffic"))

        user_installed_ca_present = any(
            "user" in {str(anchor).strip().lower() for anchor in (domain.get("trust_anchors") or [])}
            for domain in domains
        ) or any(
            "user" in {str(anchor).strip().lower() for anchor in (override.get("trust_anchors") or [])}
            for override in (network_security.get("debug_overrides") or [])
        )

        config_file_present = self._coerce_true(network_security.get("config_file_present"))
        pin_sets_present = any(int(domain.get("pin_sets") or 0) > 0 for domain in domains)
        missing_certificate_pinning = None
        if config_file_present is True:
            missing_certificate_pinning = not pin_sets_present
        elif config_file_present is False:
            missing_certificate_pinning = True

        api_call_items = list(androguard_api_calls.get("items") or [])
        password_not_hashed_in_transit = self._derive_password_not_hashed_in_transit(api_call_items)
        hostname_verifier_hits = matching_api_call_sites(
            api_call_items,
            lambda item: (
                caller_matches_package(item, package_prefix)
                and (
                    "allow_all_hostname_verifier" in api_call_signature(item).lower()
                    or "sethostnameverifier" in api_call_signature(item).lower()
                )
            ),
        )
        trust_manager_hits = matching_api_call_sites(
            api_call_items,
            lambda item: (
                caller_matches_package(item, package_prefix)
                and "checkservertrusted" in api_call_caller_signature(item).lower()
            ),
        )
        listening_port_hits = matching_api_call_sites(
            api_call_items,
            lambda item: (
                caller_matches_package(item, package_prefix)
                and any(
                    token in api_call_signature(item).lower()
                    for token in ("serversocket", "localserversocket", "datagramsocket; bind")
                )
            ),
        )
        cookie_insecurity = self._detect_cookie_security_issue(loaded_outputs, package_prefix)
        unnecessary_info = self._detect_unnecessary_information_transmission(loaded_outputs, package_prefix)
        unencrypted_transit = self._detect_unencrypted_transit_issue(
            hardcoded_values,
            cleartext_present=bool(cleartext_present),
            password_not_hashed_in_transit=password_not_hashed_in_transit,
        )

        self.allows_cleartext_traffic_for_all_domains = {
            "present": bool(cleartext_present),
            "evidence": provenance_path or first_non_empty(network_security.get("policy_source")),
        }
        self.contains_hostname_verifier_accepts_all = {
            "present": True if hostname_verifier_hits else None,
            "evidence": ", ".join(hostname_verifier_hits[:5]) if hostname_verifier_hits else "",
        }
        self.contains_x509_trust_manager_accepts_all = {
            "present": True if trust_manager_hits else None,
            "evidence": ", ".join(trust_manager_hits[:5]) if trust_manager_hits else "",
        }
        self.does_not_perform_certificate_pinning = {
            "present": missing_certificate_pinning,
            "evidence": provenance_path or first_non_empty(network_security.get("reference")),
        }
        self.opens_listening_port = {
            "present": bool(listening_port_hits) if api_call_items else None,
            "evidence": ", ".join(listening_port_hits[:5]) if listening_port_hits else "",
        }
        self.sensitive_cookies_lack_security_attributes = cookie_insecurity
        self.unnecessary_information_transmitted = unnecessary_info
        self.sensitive_information_unencrypted_in_transit = unencrypted_transit
        self.password_not_hashed_in_transit = {
            "present": password_not_hashed_in_transit["present"],
            "evidence": password_not_hashed_in_transit["evidence"],
        }
        self.weak_certificate_validation_enables_mitm = {
            "present": user_installed_ca_present,
            "evidence": provenance_path or first_non_empty(network_security.get("reference")),
        }
        self.manifest_cleartext_traffic_permitted = (
            self._coerce_true(aapt2_posture.get("cleartext_traffic_permitted"))
            if aapt2_posture
            else coerce_bool_like(aapt2_application.get("uses_cleartext_traffic"))
        )

    def _derive_password_not_hashed_in_transit(self, api_calls: list[dict[str, Any]]) -> dict[str, Any]:
        if not api_calls:
            return {"present": None, "evidence": ""}

        password_network_callers: list[str] = []
        hashed_password_callers: list[str] = []

        for item in api_calls:
            if not isinstance(item, dict):
                continue
            caller_signature = api_call_caller_signature(item)
            if not caller_signature or not self.PASSWORD_HINT_PATTERN.search(caller_signature):
                continue
            if self._is_network_api_call(item):
                password_network_callers.append(caller_signature)
            if self._is_hash_api_call(item):
                hashed_password_callers.append(caller_signature)

        password_network_callers = dedupe_preserve_order(password_network_callers)
        hashed_password_callers = dedupe_preserve_order(hashed_password_callers)
        unhashed_callers = [caller for caller in password_network_callers if caller not in set(hashed_password_callers)]

        if unhashed_callers:
            return {
                "present": True,
                "evidence": ", ".join(unhashed_callers),
            }
        if password_network_callers and hashed_password_callers:
            return {
                "present": False,
                "evidence": ", ".join(password_network_callers),
            }
        return {"present": None, "evidence": ""}

    def _detect_cookie_security_issue(self, loaded_outputs: dict[str, Any], package_prefix: str) -> dict[str, Any]:
        cookie_hits = matching_string_xrefs(
            loaded_outputs=loaded_outputs,
            value_predicate=lambda value: self.COOKIE_PATTERN.search(value) is not None,
            xref_predicate=lambda signature: package_prefix in signature.replace(".", "/") if package_prefix else False,
        )
        cookie_attr_hits = matching_string_xrefs(
            loaded_outputs=loaded_outputs,
            value_predicate=lambda value: self.COOKIE_SECURITY_ATTR_PATTERN.search(value) is not None,
            xref_predicate=lambda signature: package_prefix in signature.replace(".", "/") if package_prefix else False,
        )
        if cookie_hits and not cookie_attr_hits:
            return {"present": True, "evidence": cookie_hits[0], "details": cookie_hits[:10]}
        if cookie_hits and cookie_attr_hits:
            return {"present": False, "evidence": cookie_attr_hits[0], "details": cookie_attr_hits[:10]}
        return {"present": None, "evidence": ""}

    def _detect_unnecessary_information_transmission(
        self,
        loaded_outputs: dict[str, Any],
        package_prefix: str,
    ) -> dict[str, Any]:
        api_calls = list(((loaded_outputs.get("androguard_api_calls") or {}).get("items") or []))
        identifier_callers = set(
            matching_api_call_sites(
                api_calls,
                lambda item: (
                    caller_matches_package(item, package_prefix)
                    and any(
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
                    )
                ),
            )
        )
        network_callers = set(
            matching_api_call_sites(
                api_calls,
                lambda item: caller_matches_package(item, package_prefix) and self._is_network_api_call(item),
            )
        )
        overlapping = [caller for caller in identifier_callers if caller in network_callers]
        if overlapping:
            return {"present": True, "evidence": overlapping[0], "details": overlapping[:10]}
        if not identifier_callers:
            return {"present": False, "evidence": "no_unique_identifier_network_overlap"}
        return {"present": None, "evidence": ""}

    @staticmethod
    def _detect_unencrypted_transit_issue(
        hardcoded_values: HardcodedValuesBuilder,
        *,
        cleartext_present: bool,
        password_not_hashed_in_transit: dict[str, Any],
    ) -> dict[str, Any]:
        urls = [str(item.get("url", "")).strip() for item in hardcoded_values.urls]
        insecure_urls = [
            url
            for url in urls
            if url.lower().startswith("http://") and "localhost" not in url.lower() and "127.0.0.1" not in url
        ]
        if insecure_urls:
            return {"present": True, "evidence": insecure_urls[0], "details": insecure_urls[:10]}
        if cleartext_present and password_not_hashed_in_transit.get("present") is True:
            return {
                "present": True,
                "evidence": password_not_hashed_in_transit.get("evidence", ""),
            }
        if not cleartext_present and not insecure_urls:
            return {"present": False, "evidence": "no_http_endpoints_detected"}
        return {"present": None, "evidence": ""}

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
    def _coerce_true(value: object) -> bool:
        return str(value or "").strip().lower() == "true"
