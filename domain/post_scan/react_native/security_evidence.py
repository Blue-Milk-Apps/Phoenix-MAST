"""Derive React Native security evidence from artifacts collected during the scan."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable

from domain.post_scan.react_native.scan_extraction_context import ReactNativeScanExtractionContext


@dataclass(frozen=True)
class ReactNativeEvidenceEntry:
    present: bool | None
    evidence: str = ""
    details: list[str] = field(default_factory=list)


INSECURE_ENTITLEMENT_KEYS = frozenset(
    {
        "get-task-allow",
        "com.apple.security.cs.allow-dyld-environment-variables",
        "com.apple.security.cs.allow-unsigned-executable-memory",
        "com.apple.security.cs.disable-executable-page-protection",
        "com.apple.security.cs.disable-library-validation",
    }
)
EXTERNAL_STORAGE_PERMISSIONS = frozenset(
    {
        "android.permission.READ_EXTERNAL_STORAGE",
        "android.permission.WRITE_EXTERNAL_STORAGE",
        "android.permission.MANAGE_EXTERNAL_STORAGE",
        "android.permission.READ_MEDIA_AUDIO",
        "android.permission.READ_MEDIA_IMAGES",
        "android.permission.READ_MEDIA_VIDEO",
    }
)
WEAK_TLS_VERSIONS = frozenset({"tlsv1", "tlsv1.0", "tlsv1.1"})
IOS_SOURCE_NETWORK_CATALOG_KEYS = frozenset(
    {
        "certificate_pinning_not_implemented",
        "cleartext_http_advertiser_id",
        "cleartext_http_gps_latitude",
        "cleartext_http_gps_longitude",
        "cleartext_http_imei",
        "cleartext_http_sensitive_data",
        "cleartext_http_wifi_mac",
        "https_url_contains_gps_latitude",
        "https_url_contains_gps_longitude",
        "https_url_contains_imei",
        "https_url_contains_sensitive_data",
        "https_url_contains_wifi_mac",
        "insecure_http_traffic",
        "insecure_tls_configuration",
        "uses_ftp",
        "vulnerable_openssl_ccs_injection",
        "vulnerable_openssl_heartbleed",
    }
)


def scope_catalog_applicable(context: ReactNativeScanExtractionContext, scope: str) -> bool:
    """Return whether checks for a source scope belong in this assessment."""

    if scope == "react_native":
        return True
    if scope == "android":
        return context.platforms["android"] or context.android.get("available") is True
    if scope == "ios":
        return context.platforms["ios"] or context.ios.get("available") is True
    return False


def derived_evidence(
    context: ReactNativeScanExtractionContext,
    section: str,
) -> dict[str, ReactNativeEvidenceEntry]:
    if section == "Code":
        return _code_evidence(context)
    if section == "Network":
        return _network_evidence(context)
    if section == "Data Storage":
        return _storage_evidence(context)
    return {}


def combine_evidence_entries(
    entries: Iterable[ReactNativeEvidenceEntry],
    *,
    absent_evidence: str,
) -> ReactNativeEvidenceEntry:
    values = list(entries)
    detected = [entry for entry in values if entry.present is True]
    if detected:
        evidence = _deduplicate(entry.evidence for entry in detected if entry.evidence)
        details = _deduplicate(detail for entry in detected for detail in entry.details if detail)
        return ReactNativeEvidenceEntry(True, "; ".join(evidence[:5]), details[:10])
    if values and all(entry.present is False for entry in values):
        return ReactNativeEvidenceEntry(False, absent_evidence, [])
    return ReactNativeEvidenceEntry(None)


def _code_evidence(context: ReactNativeScanExtractionContext) -> dict[str, ReactNativeEvidenceEntry]:
    output: dict[str, ReactNativeEvidenceEntry] = {
        "contains_hard_coded_cryptographic_key": _secret_entry(
            context,
            ("cryptographic key", "encryption key", "private key", "secret key"),
            "no_hardcoded_cryptographic_key_hits",
        ),
        "contains_potential_hard_coded_password": _secret_entry(
            context,
            ("password", "passwd", "passcode", "pwd"),
            "no_hardcoded_password_hits",
        ),
        "hardcoded_api_keys_in_bundle": _secret_entry(
            context,
            ("api key", "api_key", "apikey", "api token"),
            "no_hardcoded_api_key_hits",
        ),
        "insecure_nanopb_library": _nanopb_entry(context),
    }
    if scope_catalog_applicable(context, "android"):
        application = context.mapping(context.android_metadata.get("application"))
        output.update(
            {
                "app_is_debuggable": _optional_bool(application.get("debuggable"), "debuggable"),
                "application_data_can_be_backed_up": _optional_bool(application.get("allow_backup"), "allow_backup"),
                "activities_accessible_to_other_apps": _component_entry(context, "activities"),
                "receivers_accessible_to_other_apps": _component_entry(context, "receivers"),
                "services_accessible_to_other_apps": _component_entry(context, "services"),
            }
        )
    if scope_catalog_applicable(context, "ios"):
        output["insecure_entitlements"] = _entitlement_entry(context)
    if scope_catalog_applicable(context, "android") or scope_catalog_applicable(context, "ios"):
        output["application_uses_custom_url_schemes_or_deep_links"] = _deep_link_entry(context)
    return output


def _network_evidence(context: ReactNativeScanExtractionContext) -> dict[str, ReactNativeEvidenceEntry]:
    output: dict[str, ReactNativeEvidenceEntry] = {}
    if scope_catalog_applicable(context, "android"):
        application = context.mapping(context.android_metadata.get("application"))
        output["allows_cleartext_traffic_for_all_domains"] = _optional_bool(
            application.get("uses_cleartext_traffic"), "uses_cleartext_traffic"
        )
    if scope_catalog_applicable(context, "ios"):
        output["ats_disabled"] = _ats_disabled_entry(context)
        output["ats_exceptions_configured"] = _ats_exceptions_entry(context)
        for key in IOS_SOURCE_NETWORK_CATALOG_KEYS:
            output.setdefault(key, ReactNativeEvidenceEntry(None))
    return output


def _storage_evidence(context: ReactNativeScanExtractionContext) -> dict[str, ReactNativeEvidenceEntry]:
    if not scope_catalog_applicable(context, "android"):
        return {}
    permissions = context.android_metadata.get("permissions")
    if isinstance(permissions, list):
        declared = {context.first_non_empty(item.get("name")) for item in permissions if isinstance(item, dict)}
        matches = sorted(declared & EXTERNAL_STORAGE_PERMISSIONS)
        entry = ReactNativeEvidenceEntry(
            bool(matches),
            ", ".join(matches) if matches else "no_external_storage_permissions",
            matches,
        )
    else:
        expo = context.mapping(context.source_metadata.get("expo"))
        expo_android = context.mapping(expo.get("android"))
        expo_permissions = context.string_list(expo_android.get("permissions"))
        matches = sorted(set(expo_permissions) & EXTERNAL_STORAGE_PERMISSIONS)
        entry = (
            ReactNativeEvidenceEntry(True, ", ".join(matches), matches) if matches else ReactNativeEvidenceEntry(None)
        )
    return {"accesses_external_storage": entry}


def _optional_bool(value: object, label: str) -> ReactNativeEvidenceEntry:
    if not isinstance(value, bool):
        return ReactNativeEvidenceEntry(None)
    return ReactNativeEvidenceEntry(value, f"{label}={str(value).lower()}", [])


def _component_entry(
    context: ReactNativeScanExtractionContext,
    key: str,
) -> ReactNativeEvidenceEntry:
    components = context.android_metadata.get("components")
    if not isinstance(components, dict) or not isinstance(components.get(key), list):
        return ReactNativeEvidenceEntry(None)
    values = components[key]
    exported = [
        context.first_non_empty(item.get("name"))
        for item in values
        if isinstance(item, dict) and item.get("exported") is True
    ]
    exported = [name for name in exported if name]
    if exported:
        return ReactNativeEvidenceEntry(True, f"exported_{key}={len(exported)}", exported)
    if any(isinstance(item, dict) and not isinstance(item.get("exported"), bool) for item in values):
        return ReactNativeEvidenceEntry(None)
    return ReactNativeEvidenceEntry(False, f"exported_{key}=0", [])


def _deep_link_entry(context: ReactNativeScanExtractionContext) -> ReactNativeEvidenceEntry:
    entries: list[ReactNativeEvidenceEntry] = []
    if scope_catalog_applicable(context, "android"):
        raw_links = context.android_metadata.get("deep_links")
        if isinstance(raw_links, list):
            details = [
                "://".join(
                    part
                    for part in (
                        context.first_non_empty(item.get("scheme")),
                        context.first_non_empty(item.get("host")),
                    )
                    if part
                )
                for item in raw_links
                if isinstance(item, dict)
            ]
            details = [item for item in details if item]
            entries.append(ReactNativeEvidenceEntry(bool(raw_links), f"deep_links={len(raw_links)}", details))
        else:
            entries.append(ReactNativeEvidenceEntry(None))
    if scope_catalog_applicable(context, "ios"):
        if context.ios_metadata:
            schemes = context.mapping(context.ios_metadata.get("url_schemes"))
            declared = context.string_list(schemes.get("declared_schemes"))
            entries.append(
                ReactNativeEvidenceEntry(
                    bool(declared),
                    f"declared_url_schemes={len(declared)}",
                    declared,
                )
            )
        else:
            entries.append(ReactNativeEvidenceEntry(None))
    return combine_evidence_entries(entries, absent_evidence="no_custom_url_schemes_or_deep_links")


def _secret_entry(
    context: ReactNativeScanExtractionContext,
    terms: tuple[str, ...],
    absent_evidence: str,
) -> ReactNativeEvidenceEntry:
    matches: list[str] = []
    for finding in context.gitleaks_findings:
        label = context.first_non_empty(finding.get("Description"), finding.get("RuleID"))
        if any(term in label.casefold() for term in terms):
            matches.append(_finding_location(context, finding.get("File"), finding.get("StartLine")) or label)
    for finding in context.trufflehog_findings:
        label = context.first_non_empty(finding.get("DetectorName"))
        if any(term in label.casefold() for term in terms):
            source = context.mapping(context.mapping(finding.get("SourceMetadata")).get("Data"))
            filesystem = context.mapping(source.get("Filesystem"))
            matches.append(_finding_location(context, filesystem.get("file"), filesystem.get("line")) or label)
    matches = _deduplicate(matches)
    if matches:
        return ReactNativeEvidenceEntry(True, ", ".join(matches[:5]), matches[:10])
    if context.gitleaks_assessed or context.trufflehog_assessed:
        return ReactNativeEvidenceEntry(False, absent_evidence, [])
    return ReactNativeEvidenceEntry(None)


def _nanopb_entry(context: ReactNativeScanExtractionContext) -> ReactNativeEvidenceEntry:
    matches = []
    for package in context.syft_packages:
        name = context.first_non_empty(package.get("name"))
        version = context.first_non_empty(package.get("version"))
        if "nanopb" in name.casefold() and (not version or re.match(r"^(?:0|1)\.", version)):
            matches.append(f"{name}@{version}" if version else name)
    matches = _deduplicate(matches)
    if matches:
        return ReactNativeEvidenceEntry(True, "; ".join(matches[:5]), matches[:10])
    if context.syft_assessed:
        return ReactNativeEvidenceEntry(False, "no_insecure_nanopb_library_hits", [])
    return ReactNativeEvidenceEntry(None)


def _entitlement_entry(context: ReactNativeScanExtractionContext) -> ReactNativeEvidenceEntry:
    artifacts = context.ios_metadata.get("entitlements")
    if not isinstance(artifacts, list):
        return ReactNativeEvidenceEntry(None)
    detected: set[str] = set()
    for artifact in artifacts:
        metadata = context.mapping(artifact.get("metadata")) if isinstance(artifact, dict) else {}
        detected.update(context.string_list(metadata.get("security_risk_keys")))
        detected.update(key for key in INSECURE_ENTITLEMENT_KEYS if metadata.get(key) is True)
        detected.update(str(key) for key in metadata if str(key).startswith("com.apple.private."))
    if detected:
        details = sorted(detected)
        return ReactNativeEvidenceEntry(True, ", ".join(details), details)
    if all(
        isinstance(artifact, dict)
        and isinstance(artifact.get("metadata"), dict)
        and isinstance(artifact["metadata"].get("security_risk_keys"), list)
        for artifact in artifacts
    ):
        return ReactNativeEvidenceEntry(False, "no_insecure_entitlements_hits", [])
    return ReactNativeEvidenceEntry(None)


def _ats_disabled_entry(context: ReactNativeScanExtractionContext) -> ReactNativeEvidenceEntry:
    if not context.ios_metadata:
        return ReactNativeEvidenceEntry(None)
    ats = context.mapping(context.ios_metadata.get("app_transport_security"))
    present = ats.get("allows_arbitrary_loads") is True
    return ReactNativeEvidenceEntry(
        present,
        "NSAllowsArbitraryLoads=true" if present else "NSAllowsArbitraryLoads=false",
        ["NSAllowsArbitraryLoads"] if present else [],
    )


def _ats_exceptions_entry(context: ReactNativeScanExtractionContext) -> ReactNativeEvidenceEntry:
    if not context.ios_metadata:
        return ReactNativeEvidenceEntry(None)
    ats = context.mapping(context.ios_metadata.get("app_transport_security"))
    details: list[str] = []
    if ats.get("allows_arbitrary_loads_for_media") is True:
        details.append("NSAllowsArbitraryLoadsForMedia=true")
    if ats.get("allows_arbitrary_loads_in_web_content") is True:
        details.append("NSAllowsArbitraryLoadsInWebContent=true")
    for exception in context.mapping_list(ats.get("exception_domains")):
        domain = context.first_non_empty(exception.get("domain"), "unknown domain")
        if exception.get("allows_insecure_http_loads") is True:
            details.append(f"{domain}: allows_insecure_http_loads=true")
        minimum_tls = context.first_non_empty(exception.get("minimum_tls_version"))
        if minimum_tls.casefold() in WEAK_TLS_VERSIONS:
            details.append(f"{domain}: minimum_tls_version={minimum_tls}")
        if exception.get("requires_forward_secrecy") is False:
            details.append(f"{domain}: requires_forward_secrecy=false")
    details = _deduplicate(details)
    if details:
        return ReactNativeEvidenceEntry(True, "; ".join(details[:5]), details[:10])
    return ReactNativeEvidenceEntry(False, "no_ats_metadata_exceptions", [])


def _finding_location(context: ReactNativeScanExtractionContext, raw_path: object, line: object) -> str:
    text = context.first_non_empty(raw_path)
    if text:
        path = Path(text)
        if path.is_absolute():
            try:
                text = path.relative_to(context.project_path).as_posix()
            except ValueError:
                text = path.as_posix()
    return f"{text}:{line}" if text and line not in (None, "") else text


def _deduplicate(values: Iterable[str]) -> list[str]:
    return list(dict.fromkeys(value for value in values if value))
