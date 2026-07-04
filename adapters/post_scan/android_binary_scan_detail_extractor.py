"""Android binary detail extractor for post-scan processing."""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any

from ports.scan_detail_extractor_port import ScanDetailExtractorPort


class AndroidBinaryScanDetailExtractor(ScanDetailExtractorPort):
    """Extract Android-binary-specific sections from loaded scan outputs."""

    FUNCTIONALITY_KEYS = [
        "Audio",
        "Location",
        "Contacts",
        "Geofencing",
        "Health Data",
        "Maps",
        "Networking",
        "Payment Services",
        "SMS",
        "Secure RNG",
        "Bluetooth",
        "Camera",
        "Camera Delegation",
        "Calendar",
        "Device Administrator",
        "Fingerprint",
        "Google Cloud Messaging",
        "Infrared LED",
        "In-App Purchases",
        "Keychain",
        "Microphone",
        "NFC",
        "Photos",
        "Sensors",
        "Telephony",
        "USB Devices",
    ]

    FUNCTIONALITY_CHECK_ID_MAP = {
        55: "Location",
    }

    def extract_sections(self, loaded_outputs: dict[str, Any]) -> dict[str, Any]:
        return {
            "app_info": self._build_app_info(loaded_outputs),
            "app_components": self._build_app_components(loaded_outputs),
            "certificate": self._build_certificate(loaded_outputs),
            "file_info": self._build_file_info(loaded_outputs),
            "permissions": self._build_permissions(loaded_outputs),
            "functionality": self._build_functionality(loaded_outputs),
            "hardcoded_values": self._build_hardcoded_values(loaded_outputs),
            "endpoints": self._build_endpoints(loaded_outputs),
        }

    def _build_app_info(self, loaded_outputs: dict[str, Any]) -> dict[str, str]:
        androguard_metadata = loaded_outputs.get("androguard_metadata") or {}
        aapt2_identity = loaded_outputs.get("aapt2_identity") or {}

        return {
            "icon_path": "",
            "name": self._first_non_empty(
                androguard_metadata.get("app_name"),
                aapt2_identity.get("application_label"),
            ),
            "package_name": self._first_non_empty(
                androguard_metadata.get("package"),
                aapt2_identity.get("package_name"),
            ),
            "main_activity": self._first_non_empty(aapt2_identity.get("launchable_activity")),
            "target_sdk": self._first_non_empty(
                androguard_metadata.get("target_sdk"),
                aapt2_identity.get("target_sdk_version"),
            ),
            "min_sdk": self._first_non_empty(
                androguard_metadata.get("min_sdk"),
                aapt2_identity.get("min_sdk_version"),
            ),
            "max_sdk": "",
            "version_name": self._first_non_empty(
                androguard_metadata.get("version_name"),
                aapt2_identity.get("version_name"),
            ),
            "app_store_id": "",
            "developer": "",
            "categories": "",
            "trackers_detected": "",
        }

    def _build_app_components(self, loaded_outputs: dict[str, Any]) -> dict[str, int]:
        androguard_components = loaded_outputs.get("androguard_components") or {}

        activities = androguard_components.get("activities") or []
        services = androguard_components.get("services") or []
        receivers = androguard_components.get("receivers") or []
        providers = androguard_components.get("providers") or []

        return {
            "activities": len(activities),
            "services": len(services),
            "receivers": len(receivers),
            "providers": len(providers),
            "exported_activities": self._count_exported(activities),
            "exported_services": self._count_exported(services),
            "exported_receivers": self._count_exported(receivers),
            "exported_providers": self._count_exported(providers),
        }

    def _build_certificate(self, loaded_outputs: dict[str, Any]) -> dict[str, Any]:
        androguard_certificates = loaded_outputs.get("androguard_certificates") or {}
        apksigner_signing_evidence = loaded_outputs.get("apksigner_signing_evidence") or {}

        primary_certificate = self._primary_certificate(androguard_certificates, apksigner_signing_evidence)
        subject = primary_certificate.get("subject") or {}
        issuer = primary_certificate.get("issuer") or {}
        signature_schemes = apksigner_signing_evidence.get("signature_schemes") or {}

        return {
            "owner_name": self._first_non_empty(
                subject.get("common_name"),
                self._extract_dn_value(
                    (((apksigner_signing_evidence.get("signers") or [{}])[0]).get("certificate") or {}).get(
                        "subject_dn"
                    ),
                    "CN",
                ),
            ),
            "organization": self._first_non_empty(
                subject.get("organization_name"),
                self._extract_dn_value(
                    (((apksigner_signing_evidence.get("signers") or [{}])[0]).get("certificate") or {}).get(
                        "subject_dn"
                    ),
                    "O",
                ),
            ),
            "organizational_unit": self._first_non_empty(
                subject.get("organizational_unit_name"),
                self._extract_dn_value(
                    (((apksigner_signing_evidence.get("signers") or [{}])[0]).get("certificate") or {}).get(
                        "subject_dn"
                    ),
                    "OU",
                ),
            ),
            "location": "",
            "validity": self._format_validity(
                primary_certificate.get("not_valid_before"),
                primary_certificate.get("not_valid_after"),
            ),
            "issuer": self._format_identity(issuer),
            "serial_number": self._first_non_empty(primary_certificate.get("serial_number")),
            "signature_versions": {
                "v1": self._signature_scheme_verified(signature_schemes.get("v1")),
                "v2": self._signature_scheme_verified(signature_schemes.get("v2")),
                "v3": self._signature_scheme_verified(signature_schemes.get("v3")),
                "v4": self._signature_scheme_verified(signature_schemes.get("v4")),
            },
            "hash_algorithms": self._format_hash_algorithms(primary_certificate, apksigner_signing_evidence),
            "fingerprint": self._first_non_empty(
                primary_certificate.get("sha256"),
                (((apksigner_signing_evidence.get("signers") or [{}])[0]).get("certificate") or {}).get("sha256"),
                primary_certificate.get("sha1"),
            ),
            "unique_certs": str(len(androguard_certificates.get("all") or [])),
        }

    def _build_file_info(self, loaded_outputs: dict[str, Any]) -> dict[str, str]:
        scan_metadata = loaded_outputs.get("scan_metadata") or {}
        androguard_metadata = loaded_outputs.get("androguard_metadata") or {}
        apksigner_signing_evidence = loaded_outputs.get("apksigner_signing_evidence") or {}
        apk_details = apksigner_signing_evidence.get("apk") or {}

        file_path = self._existing_file_path(
            scan_metadata.get("project_path"),
            androguard_metadata.get("apk_path"),
        )
        file_hashes = self._hash_file(file_path) if file_path else {}
        size_bytes = apk_details.get("size_bytes")
        if size_bytes in (None, "") and file_path is not None:
            size_bytes = file_path.stat().st_size

        return {
            "filename": self._first_non_empty(
                apk_details.get("file_name"),
                androguard_metadata.get("file_name"),
                Path(str(scan_metadata.get("project_path", ""))).name,
            ),
            "size": self._first_non_empty(size_bytes),
            "md5": self._first_non_empty(file_hashes.get("md5")),
            "sha1": self._first_non_empty(file_hashes.get("sha1")),
            "sha256": self._first_non_empty(
                file_hashes.get("sha256"),
                apk_details.get("sha256"),
            ),
        }

    def _build_permissions(self, loaded_outputs: dict[str, Any]) -> list[dict[str, str]]:
        aapt2_permissions = loaded_outputs.get("aapt2_permissions") or {}
        apktool_permissions = loaded_outputs.get("apktool_permissions") or {}

        declared_permissions = self._declared_permission_map(apktool_permissions)
        permissions: list[dict[str, str]] = []

        for permission in aapt2_permissions.get("permissions") or []:
            name = self._first_non_empty(permission.get("name"))
            if not name:
                continue

            protection_level = self._first_non_empty(permission.get("protection_level_hint"))
            permissions.append(
                {
                    "permission": name,
                    "status": self._normalize_permission_status(protection_level),
                    "info": self._permission_info(protection_level),
                    "usage_description": "",
                    "general_description": declared_permissions.get(name, ""),
                }
            )

        return permissions

    def _build_endpoints(self, loaded_outputs: dict[str, Any]) -> list[dict[str, str]]:
        apktool_secrets_endpoints = loaded_outputs.get("apktool_secrets_endpoints") or {}

        endpoints: list[dict[str, str]] = []
        seen: set[str] = set()

        for item in apktool_secrets_endpoints.get("items") or []:
            context = item.get("context") or {}
            category = str(context.get("category", "")).strip().lower()
            value = self._first_non_empty(item.get("value"))
            if not value:
                continue

            if category not in {"url", "domain"}:
                continue

            dedupe_key = f"{category}:{value}"
            if dedupe_key in seen:
                continue
            seen.add(dedupe_key)

            endpoints.append(
                {
                    "endpoint": value,
                    "tags": category,
                    "ip_address": "",
                    "country": "",
                }
            )

        return endpoints

    def _build_hardcoded_values(self, loaded_outputs: dict[str, Any]) -> dict[str, Any]:
        apktool_secrets_endpoints = loaded_outputs.get("apktool_secrets_endpoints") or {}

        urls: list[dict[str, str]] = []
        emails: list[str] = []
        secrets: list[dict[str, str]] = []
        seen_urls: set[str] = set()
        seen_emails: set[str] = set()
        seen_secrets: set[tuple[str, str]] = set()

        for item in apktool_secrets_endpoints.get("items") or []:
            context = item.get("context") or {}
            category = str(context.get("category", "")).strip().lower()
            value = self._first_non_empty(item.get("value"))
            if not value:
                continue

            if category == "url":
                if value in seen_urls:
                    continue
                seen_urls.add(value)
                urls.append({"url": value, "country": ""})
                continue

            if self._looks_like_email(value):
                if value in seen_emails:
                    continue
                seen_emails.add(value)
                emails.append(value)
                continue

            if category == "secret_keyword":
                location = self._format_provenance_location(item.get("provenance") or {})
                dedupe_key = (value, location)
                if dedupe_key in seen_secrets:
                    continue
                seen_secrets.add(dedupe_key)
                secrets.append({"value": value, "location": location})

        return {
            "urls": urls,
            "emails": emails,
            "secrets": secrets,
        }

    def _build_functionality(self, loaded_outputs: dict[str, Any]) -> dict[str, dict[str, Any]]:
        opengrep = loaded_outputs.get("opengrep") or {}
        functionality = {
            key: {
                "present": False,
                "explanation": "",
            }
            for key in self.FUNCTIONALITY_KEYS
        }

        for result in opengrep.get("results") or []:
            capability = self._functionality_name_for_result(result)
            if not capability or capability not in functionality:
                continue

            functionality[capability]["present"] = True
            if not functionality[capability]["explanation"]:
                functionality[capability]["explanation"] = self._functionality_explanation_for_result(result)

        return functionality

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
    def _signature_scheme_verified(signature_scheme: dict[str, Any] | None) -> bool:
        if not signature_scheme:
            return False
        return str(signature_scheme.get("state", "")).upper() == "VERIFIED"

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

        signer_cert = (((apksigner_signing_evidence.get("signers") or [{}])[0]).get("certificate") or {})
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
    def _existing_file_path(*candidates: object) -> Path | None:
        for candidate in candidates:
            text = str(candidate or "").strip()
            if not text:
                continue
            path = Path(text)
            if path.is_file():
                return path
        return None

    @staticmethod
    def _hash_file(path: Path) -> dict[str, str]:
        md5 = hashlib.md5()  # noqa: S324 - used for report metadata, not security decisions
        sha1 = hashlib.sha1()  # noqa: S324 - used for report metadata, not security decisions
        sha256 = hashlib.sha256()

        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(8192), b""):
                md5.update(chunk)
                sha1.update(chunk)
                sha256.update(chunk)

        return {
            "md5": md5.hexdigest(),
            "sha1": sha1.hexdigest(),
            "sha256": sha256.hexdigest(),
        }

    @staticmethod
    def _count_exported(components: list[dict[str, Any]]) -> int:
        return sum(1 for component in components if component.get("exported") is True)

    @staticmethod
    def _declared_permission_map(apktool_permissions: dict[str, Any]) -> dict[str, str]:
        result: dict[str, str] = {}
        for permission in apktool_permissions.get("declared") or []:
            name = str(permission.get("value", "")).strip()
            if not name:
                continue
            protection_level = str((permission.get("context") or {}).get("protection_level", "")).strip()
            if protection_level:
                result[name] = f"Declared permission ({protection_level})"
            else:
                result[name] = "Declared permission"
        return result

    @staticmethod
    def _normalize_permission_status(protection_level: str) -> str:
        normalized = protection_level.strip().lower()
        if normalized == "dangerous":
            return "dangerous"
        return "normal"

    @staticmethod
    def _permission_info(protection_level: str) -> str:
        normalized = protection_level.strip().lower()
        if normalized == "dangerous":
            return "dangerous"
        if normalized == "signature":
            return "signature"
        if normalized:
            return normalized.replace("_", " ")
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

    def _functionality_name_for_result(self, result: dict[str, Any]) -> str:
        metadata = ((result.get("extra") or {}).get("metadata") or {}).get("appcritiq") or {}

        check_id = metadata.get("check_id")
        if isinstance(check_id, int) and check_id in self.FUNCTIONALITY_CHECK_ID_MAP:
            return self.FUNCTIONALITY_CHECK_ID_MAP[check_id]

        title = str(metadata.get("title", "")).strip().lower()
        if "location" in title:
            return "Location"

        return ""

    @staticmethod
    def _functionality_explanation_for_result(result: dict[str, Any]) -> str:
        extra = result.get("extra") or {}
        metadata = (extra.get("metadata") or {}).get("appcritiq") or {}
        return (
            str(metadata.get("description", "")).strip()
            or str(metadata.get("title", "")).strip()
            or str(extra.get("message", "")).strip()
        )

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
