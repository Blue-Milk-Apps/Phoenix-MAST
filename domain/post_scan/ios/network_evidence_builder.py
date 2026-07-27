"""Build default iOS network evidence section."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

from domain.post_scan.ios.code_evidence_builder import EvidenceEntry


@dataclass
class IOSNetworkEvidence:
    ats_disabled: EvidenceEntry
    vulnerable_openssl_ccs_injection: EvidenceEntry
    uses_ftp: EvidenceEntry
    vulnerable_openssl_heartbleed: EvidenceEntry
    insecure_http_traffic: EvidenceEntry
    ats_exceptions_configured: EvidenceEntry
    cookie_missing_httponly: EvidenceEntry
    cookie_missing_secure: EvidenceEntry
    cleartext_http_advertiser_id: EvidenceEntry
    cleartext_http_imei: EvidenceEntry
    cleartext_http_gps_latitude: EvidenceEntry
    cleartext_http_gps_longitude: EvidenceEntry
    cleartext_http_sensitive_data: EvidenceEntry
    cleartext_http_wifi_mac: EvidenceEntry
    https_url_contains_imei: EvidenceEntry
    https_url_contains_gps_latitude: EvidenceEntry
    https_url_contains_gps_longitude: EvidenceEntry
    https_url_contains_sensitive_data: EvidenceEntry
    https_url_contains_wifi_mac: EvidenceEntry
    insecure_tls_configuration: EvidenceEntry
    certificate_pinning_not_implemented: EvidenceEntry

    OPENSSL_VERSION_PATTERN = re.compile(
        r"\bOpenSSL[\s_-]+(?:v)?((?:0\.9\.8|1\.0\.[01])[a-z]*)\b",
        re.IGNORECASE,
    )

    def __init__(self, loaded_outputs: dict[str, Any]) -> None:
        self.ats_disabled = self._ats_disabled_entry(loaded_outputs)
        self.vulnerable_openssl_ccs_injection = self._vulnerable_openssl_ccs_injection_entry(loaded_outputs)
        self.uses_ftp = EvidenceEntry(False, "no_uses_ftp_hits")
        self.vulnerable_openssl_heartbleed = EvidenceEntry(False, "no_vulnerable_openssl_heartbleed_hits")
        self.insecure_http_traffic = EvidenceEntry(False, "no_insecure_http_traffic_hits")
        self.ats_exceptions_configured = EvidenceEntry(False, "no_ats_exceptions_configured_hits")
        self.cookie_missing_httponly = EvidenceEntry(False, "no_cookie_missing_httponly_hits")
        self.cookie_missing_secure = EvidenceEntry(False, "no_cookie_missing_secure_hits")
        self.cleartext_http_advertiser_id = EvidenceEntry(False, "no_cleartext_http_advertiser_id_hits")
        self.cleartext_http_imei = EvidenceEntry(False, "no_cleartext_http_imei_hits")
        self.cleartext_http_gps_latitude = EvidenceEntry(False, "no_cleartext_http_gps_latitude_hits")
        self.cleartext_http_gps_longitude = EvidenceEntry(False, "no_cleartext_http_gps_longitude_hits")
        self.cleartext_http_sensitive_data = EvidenceEntry(False, "no_cleartext_http_sensitive_data_hits")
        self.cleartext_http_wifi_mac = EvidenceEntry(False, "no_cleartext_http_wifi_mac_hits")
        self.https_url_contains_imei = EvidenceEntry(False, "no_https_url_contains_imei_hits")
        self.https_url_contains_gps_latitude = EvidenceEntry(False, "no_https_url_contains_gps_latitude_hits")
        self.https_url_contains_gps_longitude = EvidenceEntry(False, "no_https_url_contains_gps_longitude_hits")
        self.https_url_contains_sensitive_data = EvidenceEntry(False, "no_https_url_contains_sensitive_data_hits")
        self.https_url_contains_wifi_mac = EvidenceEntry(False, "no_https_url_contains_wifi_mac_hits")
        self.insecure_tls_configuration = EvidenceEntry(False, "no_insecure_tls_configuration_hits")
        self.certificate_pinning_not_implemented = EvidenceEntry(False, "no_certificate_pinning_not_implemented_hits")

    @staticmethod
    def _ats_disabled_entry(loaded_outputs: dict[str, Any]) -> EvidenceEntry:
        for artifact_path, document in (loaded_outputs.get("plist_outputs") or {}).items():
            if not isinstance(document, dict) or not isinstance(document.get("app_meta"), dict):
                continue
            ats = document.get("ats")
            if isinstance(ats, dict) and ats.get("allows_arbitrary_loads") is True:
                return EvidenceEntry(
                    True,
                    f"{artifact_path}: NSAllowsArbitraryLoads=true",
                )
        return EvidenceEntry(False, "no_ats_disabled_hits")

    @classmethod
    def _vulnerable_openssl_ccs_injection_entry(
        cls,
        loaded_outputs: dict[str, Any],
    ) -> EvidenceEntry:
        for path, package_name, version in cls._syft_packages(loaded_outputs):
            if cls._is_openssl_package(package_name) and cls._is_ccs_vulnerable_openssl_version(version):
                return EvidenceEntry(True, f"{path}: {package_name}@{version}")

        strings_outputs = loaded_outputs.get("strings_outputs") or {}
        if isinstance(strings_outputs, dict):
            for path, content in strings_outputs.items():
                for version in cls.OPENSSL_VERSION_PATTERN.findall(str(content or "")):
                    if cls._is_ccs_vulnerable_openssl_version(version):
                        return EvidenceEntry(True, f"{path}: OpenSSL {version}")

        return EvidenceEntry(False, "no_vulnerable_openssl_ccs_injection_hits")

    @staticmethod
    def _is_openssl_package(package_name: str) -> bool:
        normalized = package_name.strip().lower()
        return "openssl" in normalized or normalized in {"libssl", "libssl-dev"}

    @staticmethod
    def _is_ccs_vulnerable_openssl_version(version: str) -> bool:
        match = re.fullmatch(r"(0\.9\.8|1\.0\.[01])([a-z]*)", version.strip().lower())
        if not match:
            return False

        series, suffix = match.groups()
        fixed_suffix = {"0.9.8": "za", "1.0.0": "m", "1.0.1": "h"}[series]
        return suffix < fixed_suffix

    @staticmethod
    def _syft_packages(loaded_outputs: dict[str, Any]) -> list[tuple[str, str, str]]:
        packages: list[tuple[str, str, str]] = []
        outputs = loaded_outputs.get("syft_outputs") or {}
        if not isinstance(outputs, dict):
            return packages

        for path, content in outputs.items():
            if not isinstance(content, dict):
                continue
            for collection_name in ("components", "artifacts"):
                for package in content.get(collection_name) or []:
                    if not isinstance(package, dict):
                        continue
                    name = str(package.get("name", "")).strip()
                    version = str(package.get("version", "")).strip()
                    if name and version:
                        packages.append((str(path), name, version))
        return packages
