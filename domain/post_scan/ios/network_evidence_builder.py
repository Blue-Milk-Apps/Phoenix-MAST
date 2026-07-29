"""Build default iOS network evidence section."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any
from urllib.parse import parse_qsl, urlsplit

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
    cookie_missing_secure_flag: EvidenceEntry
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
    FTP_URL_PATTERN = re.compile(r"\bftps?://[^\s'\"<>]+", re.IGNORECASE)
    HTTP_URL_PATTERN = re.compile(r"\bhttp://[^\s'\"<>]+", re.IGNORECASE)
    HTTPS_URL_PATTERN = re.compile(r"\bhttps://[^\s'\"<>]+", re.IGNORECASE)
    SET_COOKIE_PATTERN = re.compile(r"\bset-cookie\s*:\s*([^\r\n]+)", re.IGNORECASE)
    HTTPONLY_ATTRIBUTE_PATTERN = re.compile(r"\bhttponly\b", re.IGNORECASE)
    SECURE_ATTRIBUTE_PATTERN = re.compile(r"\bsecure\b", re.IGNORECASE)
    ADVERTISER_ID_PARAMETER_NAMES = {
        "idfa",
        "advertisingid",
        "advertiserid",
        "advertisingidentifier",
    }
    IMEI_PARAMETER_NAMES = {"imei", "deviceimei"}
    GPS_LATITUDE_PARAMETER_NAMES = {"latitude", "lat", "gpslatitude"}
    GPS_LONGITUDE_PARAMETER_NAMES = {"longitude", "lon", "lng", "gpslongitude"}
    SENSITIVE_DATA_PARAMETER_NAMES = {
        "password",
        "passwd",
        "pwd",
        "token",
        "accesstoken",
        "authtoken",
        "authorization",
        "session",
        "sessionid",
        "email",
        "phone",
        "ssn",
        "creditcard",
    }
    WIFI_MAC_PARAMETER_NAMES = {
        "wifimac",
        "wifimacaddress",
        "wlanmac",
        "devicemac",
    }
    INSECURE_TLS_STRING_PATTERNS = (
        re.compile(r"\bSSL_VERIFY_NONE\b", re.IGNORECASE),
        re.compile(r"\bkCFStreamSSLAllowsAnyRoot\b", re.IGNORECASE),
        re.compile(r"\bkCFStreamSSLValidatesCertificateChain\s*=\s*(?:false|0)\b", re.IGNORECASE),
        re.compile(r"\ballowsInvalidSSLCertificate\s*=\s*(?:true|1)\b", re.IGNORECASE),
        re.compile(r"\bTLSv1(?:\.0|\.1)?(?!\.)\b", re.IGNORECASE),
        re.compile(r"\bkCFStreamSocketSecurityLevelTLSv1\b", re.IGNORECASE),
    )
    WEAK_TLS_VERSIONS = {"tlsv1", "tlsv1.0", "tlsv1.1"}
    COOKIE_MISSING_HTTPONLY_RULE_ID = "ios.network.cookie-missing-httponly"
    COOKIE_MISSING_SECURE_FLAG_RULE_ID = "ios.network.cookie-missing-secure-flag"

    def __init__(self, loaded_outputs: dict[str, Any]) -> None:
        self.ats_disabled = self._ats_disabled_entry(loaded_outputs)
        self.vulnerable_openssl_ccs_injection = self._vulnerable_openssl_ccs_injection_entry(loaded_outputs)
        self.uses_ftp = self._uses_ftp_entry(loaded_outputs)
        self.vulnerable_openssl_heartbleed = self._vulnerable_openssl_heartbleed_entry(loaded_outputs)
        self.insecure_http_traffic = self._insecure_http_traffic_entry(loaded_outputs)
        self.ats_exceptions_configured = self._ats_exceptions_configured_entry(loaded_outputs)
        self.cookie_missing_httponly = self._cookie_missing_httponly_entry(loaded_outputs)
        self.cookie_missing_secure_flag = self._cookie_missing_secure_flag_entry(loaded_outputs)
        self.cleartext_http_advertiser_id = self._cleartext_http_advertiser_id_entry(loaded_outputs)
        self.cleartext_http_imei = self._cleartext_http_imei_entry(loaded_outputs)
        self.cleartext_http_gps_latitude = self._cleartext_http_gps_latitude_entry(loaded_outputs)
        self.cleartext_http_gps_longitude = self._cleartext_http_gps_longitude_entry(loaded_outputs)
        self.cleartext_http_sensitive_data = self._cleartext_http_sensitive_data_entry(loaded_outputs)
        self.cleartext_http_wifi_mac = self._cleartext_http_wifi_mac_entry(loaded_outputs)
        self.https_url_contains_imei = self._https_url_contains_imei_entry(loaded_outputs)
        self.https_url_contains_gps_latitude = self._https_url_contains_gps_latitude_entry(loaded_outputs)
        self.https_url_contains_gps_longitude = self._https_url_contains_gps_longitude_entry(loaded_outputs)
        self.https_url_contains_sensitive_data = self._https_url_contains_sensitive_data_entry(loaded_outputs)
        self.https_url_contains_wifi_mac = self._https_url_contains_wifi_mac_entry(loaded_outputs)
        self.insecure_tls_configuration = self._insecure_tls_configuration_entry(loaded_outputs)
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

    @classmethod
    def _vulnerable_openssl_heartbleed_entry(
        cls,
        loaded_outputs: dict[str, Any],
    ) -> EvidenceEntry:
        for path, package_name, version in cls._syft_packages(loaded_outputs):
            if cls._is_openssl_package(package_name) and cls._is_heartbleed_vulnerable_openssl_version(version):
                return EvidenceEntry(True, f"{path}: {package_name}@{version}")

        strings_outputs = loaded_outputs.get("strings_outputs") or {}
        if isinstance(strings_outputs, dict):
            for path, content in strings_outputs.items():
                for version in cls.OPENSSL_VERSION_PATTERN.findall(str(content or "")):
                    if cls._is_heartbleed_vulnerable_openssl_version(version):
                        return EvidenceEntry(True, f"{path}: OpenSSL {version}")

        return EvidenceEntry(False, "no_vulnerable_openssl_heartbleed_hits")

    @classmethod
    def _uses_ftp_entry(cls, loaded_outputs: dict[str, Any]) -> EvidenceEntry:
        strings_outputs = loaded_outputs.get("strings_outputs") or {}
        if isinstance(strings_outputs, dict):
            for path, content in strings_outputs.items():
                for line in str(content or "").splitlines():
                    match = cls.FTP_URL_PATTERN.search(line)
                    if match:
                        return EvidenceEntry(True, f"{path}: {match.group(0)}")

        for path, document in (loaded_outputs.get("plist_outputs") or {}).items():
            if not isinstance(document, dict) or not isinstance(document.get("app_meta"), dict):
                continue
            for value in cls._string_values(document.get("plist")):
                match = cls.FTP_URL_PATTERN.search(value)
                if match:
                    return EvidenceEntry(True, f"{path}: {match.group(0)}")

        return EvidenceEntry(False, "no_uses_ftp_hits")

    @classmethod
    def _insecure_http_traffic_entry(cls, loaded_outputs: dict[str, Any]) -> EvidenceEntry:
        strings_outputs = loaded_outputs.get("strings_outputs") or {}
        if isinstance(strings_outputs, dict):
            for path, content in strings_outputs.items():
                for line in str(content or "").splitlines():
                    for url in cls.HTTP_URL_PATTERN.findall(line):
                        if cls._is_public_http_url(url):
                            return EvidenceEntry(True, f"{path}: {url}")

        for path, document in (loaded_outputs.get("plist_outputs") or {}).items():
            if not isinstance(document, dict) or not isinstance(document.get("app_meta"), dict):
                continue
            for value in cls._string_values(document.get("plist")):
                for url in cls.HTTP_URL_PATTERN.findall(value):
                    if cls._is_public_http_url(url):
                        return EvidenceEntry(True, f"{path}: {url}")

        return EvidenceEntry(False, "no_insecure_http_traffic_hits")

    @classmethod
    def _cleartext_http_advertiser_id_entry(cls, loaded_outputs: dict[str, Any]) -> EvidenceEntry:
        return cls._url_query_parameter_entry(
            loaded_outputs,
            cls.HTTP_URL_PATTERN,
            cls.ADVERTISER_ID_PARAMETER_NAMES,
            "no_cleartext_http_advertiser_id_hits",
        )

    @classmethod
    def _cleartext_http_imei_entry(cls, loaded_outputs: dict[str, Any]) -> EvidenceEntry:
        return cls._url_query_parameter_entry(
            loaded_outputs,
            cls.HTTP_URL_PATTERN,
            cls.IMEI_PARAMETER_NAMES,
            "no_cleartext_http_imei_hits",
        )

    @classmethod
    def _cleartext_http_gps_latitude_entry(cls, loaded_outputs: dict[str, Any]) -> EvidenceEntry:
        return cls._url_query_parameter_entry(
            loaded_outputs,
            cls.HTTP_URL_PATTERN,
            cls.GPS_LATITUDE_PARAMETER_NAMES,
            "no_cleartext_http_gps_latitude_hits",
        )

    @classmethod
    def _cleartext_http_gps_longitude_entry(cls, loaded_outputs: dict[str, Any]) -> EvidenceEntry:
        return cls._url_query_parameter_entry(
            loaded_outputs,
            cls.HTTP_URL_PATTERN,
            cls.GPS_LONGITUDE_PARAMETER_NAMES,
            "no_cleartext_http_gps_longitude_hits",
        )

    @classmethod
    def _cleartext_http_sensitive_data_entry(cls, loaded_outputs: dict[str, Any]) -> EvidenceEntry:
        return cls._url_query_parameter_entry(
            loaded_outputs,
            cls.HTTP_URL_PATTERN,
            cls.SENSITIVE_DATA_PARAMETER_NAMES,
            "no_cleartext_http_sensitive_data_hits",
        )

    @classmethod
    def _cleartext_http_wifi_mac_entry(cls, loaded_outputs: dict[str, Any]) -> EvidenceEntry:
        return cls._url_query_parameter_entry(
            loaded_outputs,
            cls.HTTP_URL_PATTERN,
            cls.WIFI_MAC_PARAMETER_NAMES,
            "no_cleartext_http_wifi_mac_hits",
        )

    @classmethod
    def _https_url_contains_imei_entry(cls, loaded_outputs: dict[str, Any]) -> EvidenceEntry:
        return cls._url_query_parameter_entry(
            loaded_outputs,
            cls.HTTPS_URL_PATTERN,
            cls.IMEI_PARAMETER_NAMES,
            "no_https_url_contains_imei_hits",
        )

    @classmethod
    def _https_url_contains_gps_latitude_entry(cls, loaded_outputs: dict[str, Any]) -> EvidenceEntry:
        return cls._url_query_parameter_entry(
            loaded_outputs,
            cls.HTTPS_URL_PATTERN,
            cls.GPS_LATITUDE_PARAMETER_NAMES,
            "no_https_url_contains_gps_latitude_hits",
        )

    @classmethod
    def _https_url_contains_gps_longitude_entry(cls, loaded_outputs: dict[str, Any]) -> EvidenceEntry:
        return cls._url_query_parameter_entry(
            loaded_outputs,
            cls.HTTPS_URL_PATTERN,
            cls.GPS_LONGITUDE_PARAMETER_NAMES,
            "no_https_url_contains_gps_longitude_hits",
        )

    @classmethod
    def _https_url_contains_sensitive_data_entry(cls, loaded_outputs: dict[str, Any]) -> EvidenceEntry:
        return cls._url_query_parameter_entry(
            loaded_outputs,
            cls.HTTPS_URL_PATTERN,
            cls.SENSITIVE_DATA_PARAMETER_NAMES,
            "no_https_url_contains_sensitive_data_hits",
        )

    @classmethod
    def _https_url_contains_wifi_mac_entry(cls, loaded_outputs: dict[str, Any]) -> EvidenceEntry:
        return cls._url_query_parameter_entry(
            loaded_outputs,
            cls.HTTPS_URL_PATTERN,
            cls.WIFI_MAC_PARAMETER_NAMES,
            "no_https_url_contains_wifi_mac_hits",
        )

    @classmethod
    def _url_query_parameter_entry(
        cls,
        loaded_outputs: dict[str, Any],
        url_pattern: re.Pattern[str],
        parameter_names: set[str],
        no_hits_evidence: str,
    ) -> EvidenceEntry:
        strings_outputs = loaded_outputs.get("strings_outputs") or {}
        if isinstance(strings_outputs, dict):
            for path, content in strings_outputs.items():
                for line in str(content or "").splitlines():
                    for url in url_pattern.findall(line):
                        if cls._is_public_http_url(url) and cls._contains_query_parameter(url, parameter_names):
                            return EvidenceEntry(True, f"{path}: {url}")

        return EvidenceEntry(False, no_hits_evidence)

    @classmethod
    def _insecure_tls_configuration_entry(cls, loaded_outputs: dict[str, Any]) -> EvidenceEntry:
        for path, document in (loaded_outputs.get("plist_outputs") or {}).items():
            if not isinstance(document, dict) or not isinstance(document.get("app_meta"), dict):
                continue
            ats = document.get("ats")
            if not isinstance(ats, dict):
                continue
            for exception in ats.get("exception_domains") or []:
                if not isinstance(exception, dict):
                    continue
                domain = str(exception.get("domain", "")).strip() or "unknown domain"
                minimum_tls_version = str(exception.get("minimum_tls_version", "")).strip().lower()
                if minimum_tls_version in cls.WEAK_TLS_VERSIONS:
                    return EvidenceEntry(
                        True,
                        f"{path}: {domain} (NSExceptionMinimumTLSVersion={exception['minimum_tls_version']})",
                    )
                if exception.get("requires_forward_secrecy") is False:
                    return EvidenceEntry(
                        True,
                        f"{path}: {domain} (NSExceptionRequiresForwardSecrecy=false)",
                    )

        strings_outputs = loaded_outputs.get("strings_outputs") or {}
        if isinstance(strings_outputs, dict):
            for path, content in strings_outputs.items():
                for line in str(content or "").splitlines():
                    for pattern in cls.INSECURE_TLS_STRING_PATTERNS:
                        match = pattern.search(line)
                        if match:
                            return EvidenceEntry(True, f"{path}: {match.group(0)}")

        return EvidenceEntry(False, "no_insecure_tls_configuration_hits")

    @classmethod
    def _ats_exceptions_configured_entry(cls, loaded_outputs: dict[str, Any]) -> EvidenceEntry:
        for path, document in (loaded_outputs.get("plist_outputs") or {}).items():
            if not isinstance(document, dict) or not isinstance(document.get("app_meta"), dict):
                continue
            ats = document.get("ats")
            if not isinstance(ats, dict):
                continue
            if ats.get("allows_arbitrary_loads_for_media") is True:
                return EvidenceEntry(True, f"{path}: NSAllowsArbitraryLoadsForMedia=true")
            if ats.get("allows_arbitrary_loads_in_web_content") is True:
                return EvidenceEntry(True, f"{path}: NSAllowsArbitraryLoadsInWebContent=true")
            for exception in ats.get("exception_domains") or []:
                if not isinstance(exception, dict):
                    continue
                domain = str(exception.get("domain", "")).strip() or "unknown domain"
                if exception.get("allows_insecure_http_loads") is True:
                    return EvidenceEntry(
                        True,
                        f"{path}: {domain} (NSExceptionAllowsInsecureHTTPLoads=true)",
                    )
                minimum_tls_version = str(exception.get("minimum_tls_version", "")).strip().lower()
                if minimum_tls_version in cls.WEAK_TLS_VERSIONS:
                    return EvidenceEntry(
                        True,
                        f"{path}: {domain} (NSExceptionMinimumTLSVersion={exception['minimum_tls_version']})",
                    )
                if exception.get("requires_forward_secrecy") is False:
                    return EvidenceEntry(
                        True,
                        f"{path}: {domain} (NSExceptionRequiresForwardSecrecy=false)",
                    )
        return EvidenceEntry(False, "no_ats_exceptions_configured_hits")

    @classmethod
    def _cookie_missing_httponly_entry(cls, loaded_outputs: dict[str, Any]) -> EvidenceEntry:
        for result in (loaded_outputs.get("opengrep") or {}).get("results") or []:
            if not isinstance(result, dict) or result.get("check_id") != cls.COOKIE_MISSING_HTTPONLY_RULE_ID:
                continue
            extra = result.get("extra") or {}
            evidence = str(extra.get("lines") or extra.get("message") or result.get("check_id")).strip()
            path = str(result.get("path", "")).strip()
            return EvidenceEntry(True, f"{path}: {evidence}" if path else evidence)

        strings_outputs = loaded_outputs.get("strings_outputs") or {}
        if isinstance(strings_outputs, dict):
            for path, content in strings_outputs.items():
                for cookie_value in cls.SET_COOKIE_PATTERN.findall(str(content or "")):
                    if not cls.HTTPONLY_ATTRIBUTE_PATTERN.search(cookie_value):
                        return EvidenceEntry(True, f"{path}: Set-Cookie: {cookie_value}")

        return EvidenceEntry(False, "no_cookie_missing_httponly_hits")

    @classmethod
    def _cookie_missing_secure_flag_entry(cls, loaded_outputs: dict[str, Any]) -> EvidenceEntry:
        for result in (loaded_outputs.get("opengrep") or {}).get("results") or []:
            if not isinstance(result, dict) or result.get("check_id") != cls.COOKIE_MISSING_SECURE_FLAG_RULE_ID:
                continue
            extra = result.get("extra") or {}
            evidence = str(extra.get("lines") or extra.get("message") or result.get("check_id")).strip()
            path = str(result.get("path", "")).strip()
            return EvidenceEntry(True, f"{path}: {evidence}" if path else evidence)

        strings_outputs = loaded_outputs.get("strings_outputs") or {}
        if isinstance(strings_outputs, dict):
            for path, content in strings_outputs.items():
                for cookie_value in cls.SET_COOKIE_PATTERN.findall(str(content or "")):
                    if not cls.SECURE_ATTRIBUTE_PATTERN.search(cookie_value):
                        return EvidenceEntry(True, f"{path}: Set-Cookie: {cookie_value}")

        return EvidenceEntry(False, "no_cookie_missing_secure_flag_hits")

    @staticmethod
    def _is_public_http_url(url: str) -> bool:
        try:
            parsed = urlsplit(url)
        except ValueError:
            return False
        hostname = (parsed.hostname or "").lower()
        if not hostname:
            return False
        if hostname in {"localhost", "127.0.0.1", "::1"}:
            return False
        return not (hostname == "www.apple.com" and parsed.path.lower().startswith("/dtds/"))

    @staticmethod
    def _contains_query_parameter(url: str, parameter_names: set[str]) -> bool:
        try:
            query_parameters = parse_qsl(urlsplit(url).query, keep_blank_values=True)
        except ValueError:
            return False
        return any(
            parameter_name.lower().replace("_", "").replace("-", "") in parameter_names
            for parameter_name, _ in query_parameters
        )

    @classmethod
    def _string_values(cls, value: Any) -> list[str]:
        if isinstance(value, str):
            return [value]
        if isinstance(value, dict):
            return [item for nested_value in value.values() for item in cls._string_values(nested_value)]
        if isinstance(value, list):
            return [item for nested_value in value for item in cls._string_values(nested_value)]
        return []

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
    def _is_heartbleed_vulnerable_openssl_version(version: str) -> bool:
        match = re.fullmatch(r"1\.0\.1([a-z]*)", version.strip().lower())
        return match is not None and match.group(1) < "g"

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
