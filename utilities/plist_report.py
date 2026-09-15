"""Shared plist report formatting for source and binary scanners."""

from __future__ import annotations

import json
import plistlib
from pathlib import Path

from domain.models import ScanResult, ScanType
from utilities.json_utils import json_safe


class PlistReportBuilder:
    """Build normalized plist scan artifacts with consistent JSON schemas."""

    SENSITIVE_NAME_PARTS = (
        "api_key",
        "apikey",
        "auth",
        "credential",
        "password",
        "secret",
        "token",
    )

    def __init__(
        self,
        *,
        scanner_name: str,
        scan_type: ScanType,
        description: str,
        base_path: Path,
        output_format: str,
    ) -> None:
        self.scanner_name = scanner_name
        self.scan_type = scan_type
        self.description = description
        self.base_path = base_path
        self.output_format = output_format

    def build(self, plist_files: list[Path]) -> list[ScanResult]:
        if self.output_format == "xml":
            return self._xml_results(plist_files)
        return self._json_results(plist_files)

    def _json_results(self, plist_files: list[Path]) -> list[ScanResult]:
        results: list[ScanResult] = []
        index_entries: list[dict[str, object]] = []
        parse_failures = 0

        for plist_file in plist_files:
            relative_target = self._output_path_for_plist(plist_file)
            source_path = self._source_path(plist_file)
            try:
                data = self._load_plist(plist_file)
                plist_type = self._classify_plist(plist_file, data)
                role = self._artifact_role(plist_type, plist_file, data)
                if not self._should_emit_plist(plist_type, plist_file, data):
                    index_entries.append(
                        {
                            "key_count": self._key_count(data),
                            "output_path": "",
                            "parse_status": "success",
                            "plist_type": plist_type,
                            "role": role,
                            "source_path": source_path,
                            "skipped": True,
                            "skip_reason": "non_app_plist",
                        }
                    )
                    continue

                index_entries.append(
                    {
                        "key_count": self._key_count(data),
                        "output_path": relative_target.as_posix(),
                        "parse_status": "success",
                        "plist_type": plist_type,
                        "role": role,
                        "source_path": source_path,
                        "skipped": False,
                    }
                )
                results.append(
                    ScanResult(
                        scanner_name=self.scanner_name,
                        scan_type=self.scan_type,
                        success=True,
                        raw_output=self._serialize_plist(
                            plist_file,
                            data,
                            plist_type,
                        ),
                        relative_target_path=relative_target.as_posix(),
                        description=self.description,
                    )
                )
            except Exception as exc:
                parse_failures += 1
                index_entries.append(
                    {
                        "error": str(exc),
                        "output_path": relative_target.as_posix(),
                        "parse_status": "failed",
                        "source_path": source_path,
                        "skipped": False,
                    }
                )
                results.append(
                    ScanResult(
                        scanner_name=self.scanner_name,
                        scan_type=self.scan_type,
                        success=False,
                        error_message=str(exc),
                        raw_output=json.dumps(
                            {
                                "error": str(exc),
                                "success": False,
                            },
                            indent=2,
                            sort_keys=True,
                        ),
                        relative_target_path=relative_target.as_posix(),
                    )
                )

        results.append(
            ScanResult(
                scanner_name=self.scanner_name,
                scan_type=self.scan_type,
                success=parse_failures == 0,
                error_message="" if parse_failures == 0 else "One or more plist files could not be parsed.",
                raw_output=json.dumps(
                    {
                        "emitted_plist_count": sum(1 for entry in index_entries if not entry.get("skipped"))
                        - parse_failures,
                        "parse_failures": parse_failures,
                        "plist_count": len(index_entries),
                        "plists": index_entries,
                        "skipped_plist_count": sum(1 for entry in index_entries if entry.get("skipped")),
                    },
                    indent=2,
                    sort_keys=True,
                ),
                relative_target_path="scan_index.json",
                description="Index of plist files discovered during scanning.",
            )
        )
        return results

    def _xml_results(self, plist_files: list[Path]) -> list[ScanResult]:
        results: list[ScanResult] = []
        for plist_file in plist_files:
            relative_target = self._output_path_for_plist(plist_file)
            try:
                data = self._load_plist(plist_file)
                results.append(
                    ScanResult(
                        scanner_name=self.scanner_name,
                        scan_type=self.scan_type,
                        success=True,
                        raw_output=plistlib.dumps(data, fmt=plistlib.FMT_XML, sort_keys=True).decode("utf-8"),
                        relative_target_path=relative_target.as_posix(),
                        description=self.description,
                    )
                )
            except Exception as exc:
                results.append(
                    ScanResult(
                        scanner_name=self.scanner_name,
                        scan_type=self.scan_type,
                        success=False,
                        error_message=str(exc),
                        raw_output=json.dumps(
                            {
                                "error": str(exc),
                                "success": False,
                            },
                            indent=2,
                            sort_keys=True,
                        ),
                        relative_target_path=relative_target.as_posix(),
                    )
                )
        return results

    def _load_plist(self, plist_file: Path) -> object:
        with plist_file.open("rb") as handle:
            return plistlib.load(handle)

    def _output_path_for_plist(self, plist_file: Path) -> Path:
        try:
            relative = plist_file.relative_to(self.base_path)
        except ValueError:
            relative = Path(plist_file.name)

        if relative == Path(".") or not relative.parts:
            relative = Path(plist_file.name)

        if relative.suffix.lower() == ".plist":
            return relative.with_suffix(f".{self.output_format}")
        return relative.with_name(f"{relative.name}.{self.output_format}")

    def _serialize_plist(
        self,
        plist_file: Path,
        data: object,
        plist_type: str,
    ) -> str:
        role = self._artifact_role(plist_type, plist_file, data)
        if role == "app":
            payload = {
                "app_meta": self._app_meta(data),
                "ats": self._transport_security_details(data),
                "background_modes": self._background_modes(data),
                "entitlements": self._entitlement_details(data),
                "other_important_items": self._other_important_items(data),
                "plist": json_safe(data),
                "privacy": {
                    "permissions": self._permission_details(data),
                },
                "url_schemes": self._url_scheme_details(data),
            }
        elif role == "framework":
            payload = {
                "framework_meta": self._framework_meta(data),
                "important_items": self._framework_important_items(data),
                "plist": json_safe(data),
            }
        elif role == "entitlements":
            payload = {
                "entitlements": self._entitlement_details(data),
                "plist": json_safe(data),
                "plist_type": plist_type,
            }
        elif role == "privacy_manifest":
            payload = {
                "plist": json_safe(data),
                "plist_type": plist_type,
                "privacy_manifest": self._privacy_manifest_details(data),
            }
        else:
            payload = {
                "important_items": self._generic_important_items(data),
                "plist": json_safe(data),
                "plist_type": plist_type,
            }
        return json.dumps(payload, indent=2, sort_keys=True)

    def _classify_plist(self, plist_file: Path, data: object) -> str:
        relative_parts = [part.lower() for part in self._source_path(plist_file).split("/")]
        name = plist_file.name.lower()
        keys = set(data) if isinstance(data, dict) else set()

        if plist_file.suffix.lower() == ".xcprivacy" or name == "privacyinfo.xcprivacy":
            return "privacy_manifest"
        if plist_file.suffix.lower() == ".entitlements":
            return "entitlements_plist"
        if name == "info.plist" and {"CFBundleIdentifier", "CFBundlePackageType"} & keys:
            return "ios_info_plist"
        if "entitlements" in name or any(str(key).startswith("com.apple.developer.") for key in keys):
            return "entitlements_plist"
        if any(part.endswith((".xcodeproj", ".xcworkspace")) for part in relative_parts):
            return "xcode_project_plist"
        if "xcassets" in relative_parts or name == "assets.plist":
            return "asset_catalog_plist"
        if any(part in name for part in self.SENSITIVE_NAME_PARTS) or "preferences" in relative_parts:
            return "credentials_or_preferences_plist"
        return "unknown_plist"

    def _should_emit_plist(self, plist_type: str, plist_file: Path, data: object) -> bool:
        if plist_type in {"credentials_or_preferences_plist", "entitlements_plist", "privacy_manifest"}:
            return True
        if plist_type == "ios_info_plist":
            return self._bundle_role(plist_file, data) in {"app", "framework"}
        if self._has_sensitive_key(data):
            return True
        return False

    def _artifact_role(self, plist_type: str, plist_file: Path, data: object) -> str:
        if plist_type == "ios_info_plist":
            return self._bundle_role(plist_file, data)
        if plist_type == "entitlements_plist":
            return "entitlements"
        if plist_type == "privacy_manifest":
            return "privacy_manifest"
        if plist_type == "credentials_or_preferences_plist":
            return "security_relevant"
        if self._has_sensitive_key(data):
            return "security_relevant"
        return "skipped"

    def _bundle_role(self, plist_file: Path, data: object) -> str:
        if not isinstance(data, dict):
            return "other"

        package_type = str(data.get("CFBundlePackageType", "")).upper()
        source_path = self._source_path(plist_file).lower()
        if package_type == "APPL" or data.get("LSRequiresIPhoneOS") is True:
            return "app"
        if package_type == "FMWK" or ".framework/" in source_path or source_path.endswith(".framework/info.plist"):
            return "framework"
        if plist_file.name.lower() == "info.plist":
            return "app"
        return "other"

    def _app_meta(self, data: object) -> dict[str, object]:
        if not isinstance(data, dict):
            return {}

        return json_safe(
            {
                "bundle_identifier": data.get("CFBundleIdentifier", ""),
                "bundle_name": data.get("CFBundleName", ""),
                "build": data.get("CFBundleVersion", ""),
                "display_name": data.get("CFBundleDisplayName", ""),
                "executable": data.get("CFBundleExecutable", ""),
                "minimum_os": data.get("MinimumOSVersion", ""),
                "package_type": data.get("CFBundlePackageType", ""),
                "required_device_capabilities": data.get("UIRequiredDeviceCapabilities", []),
                "requires_iphone_os": data.get("LSRequiresIPhoneOS", False),
                "supported_interface_orientations": data.get("UISupportedInterfaceOrientations", []),
                "supported_platforms": data.get("CFBundleSupportedPlatforms", []),
                "version": data.get("CFBundleShortVersionString", ""),
            }
        )

    def _framework_meta(self, data: object) -> dict[str, object]:
        if not isinstance(data, dict):
            return {}

        return json_safe(
            {
                "bundle_identifier": data.get("CFBundleIdentifier", ""),
                "bundle_name": data.get("CFBundleName", ""),
                "build": data.get("CFBundleVersion", ""),
                "display_name": data.get("CFBundleDisplayName", ""),
                "executable": data.get("CFBundleExecutable", ""),
                "minimum_os": data.get("MinimumOSVersion", ""),
                "package_type": data.get("CFBundlePackageType", ""),
                "version": data.get("CFBundleShortVersionString", ""),
            }
        )

    def _background_modes(self, data: object) -> list[object]:
        if not isinstance(data, dict):
            return []
        value = data.get("UIBackgroundModes", [])
        return json_safe(value if isinstance(value, list) else [value])

    def _other_important_items(self, data: object) -> dict[str, object]:
        if not isinstance(data, dict):
            return {}

        return json_safe(
            {
                "custom_fonts": data.get("UIAppFonts", []),
                "document_types": data.get("CFBundleDocumentTypes", []),
                "exported_type_identifiers": data.get("UTExportedTypeDeclarations", []),
                "imported_type_identifiers": data.get("UTImportedTypeDeclarations", []),
            }
        )

    def _framework_important_items(self, data: object) -> dict[str, object]:
        if not isinstance(data, dict):
            return {}

        return json_safe(
            {
                "ats": self._transport_security_details(data),
                "privacy": {
                    "permissions": self._permission_details(data),
                },
                "url_schemes": self._url_scheme_details(data),
            }
        )

    def _generic_important_items(self, data: object) -> dict[str, object]:
        if not isinstance(data, dict):
            return {}

        return json_safe(
            {
                "app_meta": self._app_meta(data),
                "ats": self._transport_security_details(data),
                "entitlements": self._entitlement_details(data),
                "privacy": {
                    "permissions": self._permission_details(data),
                },
                "url_schemes": self._url_scheme_details(data),
            }
        )

    def _entitlement_details(self, data: object) -> dict[str, object]:
        if not isinstance(data, dict):
            return {}

        entitlement_keys = {
            "application-identifier",
            "aps-environment",
            "com.apple.developer.associated-domains",
            "com.apple.developer.healthkit",
            "com.apple.developer.icloud-container-identifiers",
            "com.apple.developer.in-app-payments",
            "com.apple.security.application-groups",
            "keychain-access-groups",
        }
        if not entitlement_keys.intersection(data):
            return {}

        return json_safe(
            {
                "application_groups": data.get("com.apple.security.application-groups", []),
                "application_identifier": data.get("application-identifier", ""),
                "aps_environment": data.get("aps-environment", ""),
                "associated_domains": data.get("com.apple.developer.associated-domains", []),
                "healthkit": data.get("com.apple.developer.healthkit", False),
                "icloud_containers": data.get("com.apple.developer.icloud-container-identifiers", []),
                "in_app_payments": data.get("com.apple.developer.in-app-payments", []),
                "keychain_access_groups": data.get("keychain-access-groups", []),
            }
        )

    def _privacy_manifest_details(self, data: object) -> dict[str, object]:
        if not isinstance(data, dict):
            return {}

        return json_safe(
            {
                "accessed_api_types": data.get("NSPrivacyAccessedAPITypes", []),
                "collected_data_types": data.get("NSPrivacyCollectedDataTypes", []),
                "tracking": data.get("NSPrivacyTracking") is True,
                "tracking_domains": data.get("NSPrivacyTrackingDomains", []),
            }
        )

    def _permission_details(self, data: object) -> list[dict[str, object]]:
        if not isinstance(data, dict):
            return []

        return [
            {
                "key": str(key),
                "purpose": str(value),
            }
            for key, value in sorted(data.items())
            if str(key).endswith("UsageDescription")
        ]

    def _transport_security_details(self, data: object) -> dict[str, object]:
        if not isinstance(data, dict):
            return {}

        ats = data.get("NSAppTransportSecurity")
        if not isinstance(ats, dict):
            return {}

        exception_domains = []
        exceptions = ats.get("NSExceptionDomains")
        if isinstance(exceptions, dict):
            for domain, settings in sorted(exceptions.items()):
                settings = settings if isinstance(settings, dict) else {}
                allows_insecure_http_loads = settings.get("NSExceptionAllowsInsecureHTTPLoads")
                third_party_allows_insecure_http_loads = settings.get(
                    "NSThirdPartyExceptionAllowsInsecureHTTPLoads"  # pragma: allowlist secret
                )
                minimum_tls_version = settings.get("NSExceptionMinimumTLSVersion")
                third_party_minimum_tls_version = settings.get("NSThirdPartyExceptionMinimumTLSVersion")
                requires_forward_secrecy = settings.get("NSExceptionRequiresForwardSecrecy")
                third_party_requires_forward_secrecy = settings.get("NSThirdPartyExceptionRequiresForwardSecrecy")
                forward_secrecy_values = [
                    requires_forward_secrecy,
                    third_party_requires_forward_secrecy,
                ]
                if any(value is False for value in forward_secrecy_values):
                    requires_forward_secrecy = False
                elif any(value is True for value in forward_secrecy_values):
                    requires_forward_secrecy = True
                else:
                    requires_forward_secrecy = None
                exception_domains.append(
                    {
                        "allows_insecure_http_loads": (
                            allows_insecure_http_loads is True or third_party_allows_insecure_http_loads is True
                        ),
                        "domain": domain,
                        "minimum_tls_version": minimum_tls_version or third_party_minimum_tls_version or "",
                        "requires_forward_secrecy": requires_forward_secrecy,
                    }
                )

        return json_safe(
            {
                "allows_arbitrary_loads": ats.get("NSAllowsArbitraryLoads") is True,
                "allows_arbitrary_loads_for_media": (ats.get("NSAllowsArbitraryLoadsForMedia") is True),
                "allows_arbitrary_loads_in_web_content": (ats.get("NSAllowsArbitraryLoadsInWebContent") is True),
                "exception_domains": exception_domains,
            }
        )

    def _url_scheme_details(self, data: object) -> dict[str, object]:
        if not isinstance(data, dict):
            return {}

        bundle_schemes = self._bundle_url_schemes(data)
        queried_schemes = data.get("LSApplicationQueriesSchemes", [])
        if not bundle_schemes and not queried_schemes:
            return {}

        return json_safe(
            {
                "declared_schemes": bundle_schemes,
                "queried_schemes": queried_schemes,
            }
        )

    @staticmethod
    def _bundle_url_schemes(data: dict[object, object]) -> list[object]:
        schemes: list[object] = []
        for url_type in data.get("CFBundleURLTypes", []):
            if isinstance(url_type, dict):
                url_schemes = url_type.get("CFBundleURLSchemes", [])
                if isinstance(url_schemes, list):
                    schemes.extend(url_schemes)
        return schemes

    @staticmethod
    def _key_count(data: object) -> int:
        return len(data) if isinstance(data, dict) else 0

    def _has_sensitive_key(self, data: object) -> bool:
        for path, value in self._walk_values(data):
            lowered_path = path.lower()
            if any(part in lowered_path for part in self.SENSITIVE_NAME_PARTS):
                return True
        return False

    def _walk_values(self, value: object, prefix: str = "") -> list[tuple[str, object]]:
        items: list[tuple[str, object]] = []
        if isinstance(value, dict):
            for key, child in value.items():
                key_path = f"{prefix}.{key}" if prefix else str(key)
                items.append((key_path, child))
                items.extend(self._walk_values(child, key_path))
        elif isinstance(value, list):
            for index, child in enumerate(value):
                key_path = f"{prefix}[{index}]"
                items.extend(self._walk_values(child, key_path))
        return items

    def _source_path(self, plist_file: Path) -> str:
        try:
            return plist_file.relative_to(self.base_path).as_posix()
        except ValueError:
            return plist_file.name
