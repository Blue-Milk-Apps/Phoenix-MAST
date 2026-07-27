"""Build default iOS network evidence section."""

from __future__ import annotations

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

    def __init__(self, loaded_outputs: dict[str, Any]) -> None:
        self.ats_disabled = self._ats_disabled_entry(loaded_outputs)
        self.vulnerable_openssl_ccs_injection = EvidenceEntry(False, "no_vulnerable_openssl_ccs_injection_hits")
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
