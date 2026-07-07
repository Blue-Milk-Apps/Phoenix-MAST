"""Android binary detail extractor for post-scan processing."""

from __future__ import annotations

import hashlib
import re
from pathlib import Path
from typing import Any

from ports.scan_detail_extractor_port import ScanDetailExtractorPort


class AndroidBinaryScanDetailExtractor(ScanDetailExtractorPort):
    """Extract Android-binary-specific sections from loaded scan outputs."""

    ENCODED_SECRET_PATTERN = re.compile(
        r"(?<![A-Za-z0-9+/=])[A-Za-z0-9+/]{40,}={0,2}(?![A-Za-z0-9+/=])"
    )
    JVM_DESCRIPTOR_PATTERN = re.compile(r"^\+?L(?:[A-Za-z0-9_$]+/)+[A-Za-z0-9_$]+$")
    SECRET_LABEL_PATTERN = re.compile(
        r"(?i)^(?:api[_-]?key|client[_-]?secret|secret[_-]?key|access[_-]?token|secretkey)$"
    )
    STORAGE_CREDENTIAL_HINT_PATTERN = re.compile(
        r"(?i)(?:auth|credential|login|passw(?:or)?d|token|session|rememberme)"
    )
    EXTERNAL_STORAGE_PERMISSIONS = {
        "android.permission.READ_EXTERNAL_STORAGE",
        "android.permission.WRITE_EXTERNAL_STORAGE",
        "android.permission.MANAGE_EXTERNAL_STORAGE",
        "android.permission.READ_MEDIA_AUDIO",
        "android.permission.READ_MEDIA_IMAGES",
        "android.permission.READ_MEDIA_VIDEO",
        "android.permission.READ_MEDIA_VISUAL_USER_SELECTED",
    }
    ANDROID_PERMISSION_DESCRIPTIONS = {
        "android.permission.ACCESS_COARSE_LOCATION": "Allows the app to access approximate location derived from network-based sources such as Wi-Fi and cell towers.",
        "android.permission.ACCESS_FINE_LOCATION": "Allows the app to access precise location from GPS and other location providers.",
        "android.permission.ACCESS_NETWORK_STATE": "Allows the app to view network connections and determine whether connectivity is available.",
        "android.permission.ACCESS_WIFI_STATE": "Allows the app to view information about Wi-Fi networking.",
        "android.permission.BLUETOOTH": "Allows the app to connect to paired Bluetooth devices.",
        "android.permission.BLUETOOTH_ADMIN": "Allows the app to configure local Bluetooth settings and discover remote devices.",
        "android.permission.BLUETOOTH_CONNECT": "Allows the app to connect to nearby Bluetooth devices.",
        "android.permission.BLUETOOTH_SCAN": "Allows the app to discover and scan for nearby Bluetooth devices.",
        "android.permission.CALL_PHONE": "Allows the app to initiate phone calls without going through the dialer.",
        "android.permission.CAMERA": "Allows the app to access the device camera.",
        "android.permission.GET_ACCOUNTS": "Allows the app to access the list of accounts registered on the device.",
        "android.permission.INTERNET": "Allows the app to open network sockets and communicate over the internet.",
        "android.permission.NFC": "Allows the app to communicate using Near Field Communication.",
        "android.permission.POST_NOTIFICATIONS": "Allows the app to send notifications to the user.",
        "android.permission.READ_CALENDAR": "Allows the app to read calendar events and related details stored on the device.",
        "android.permission.READ_CALL_LOG": "Allows the app to read the device call log.",
        "android.permission.READ_CONTACTS": "Allows the app to read the user's contacts data.",
        "android.permission.READ_EXTERNAL_STORAGE": "Allows the app to read files from shared external storage.",
        "android.permission.READ_MEDIA_AUDIO": "Allows the app to read audio files from shared storage.",
        "android.permission.READ_MEDIA_IMAGES": "Allows the app to read image files from shared storage.",
        "android.permission.READ_MEDIA_VIDEO": "Allows the app to read video files from shared storage.",
        "android.permission.READ_PHONE_STATE": "Allows the app to access phone state information such as the current cellular network and ongoing call status.",
        "android.permission.READ_PROFILE": "Allows the app to read the user's personal profile data stored on the device.",
        "android.permission.READ_SMS": "Allows the app to read SMS messages stored on the device.",
        "android.permission.READ_SYNC_SETTINGS": "Allows the app to read the sync settings for an account.",
        "android.permission.RECEIVE_BOOT_COMPLETED": "Allows the app to start automatically after the device finishes booting.",
        "android.permission.RECEIVE_SMS": "Allows the app to receive and process incoming SMS messages.",
        "android.permission.RECORD_AUDIO": "Allows the app to capture audio using the microphone.",
        "android.permission.SEND_SMS": "Allows the app to send SMS messages.",
        "android.permission.USE_BIOMETRIC": "Allows the app to use biometric authentication such as fingerprint or face recognition.",
        "android.permission.USE_CREDENTIALS": "Allows the app to request authentication tokens from the account manager.",
        "android.permission.USE_FINGERPRINT": "Allows the app to use fingerprint hardware for authentication.",
        "android.permission.WRITE_CALENDAR": "Allows the app to create or modify calendar events.",
        "android.permission.WRITE_CONTACTS": "Allows the app to create or modify the user's contacts data.",
        "android.permission.WRITE_EXTERNAL_STORAGE": "Allows the app to write files to shared external storage.",
        "android.permission.WRITE_SETTINGS": "Allows the app to modify system settings.",
        "android.permission.WRITE_SMS": "Allows the app to create or modify SMS messages stored on the device.",
    }

    FUNCTIONALITY_KEYS = [
        "Audio",
        "Background Execution",
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
        "Keystore",
        "Microphone",
        "NFC",
        "Photos",
        "Sensors",
        "Telephony",
        "USB Devices",
    ]

    FUNCTIONALITY_CHECK_ID_MAP = {
        9: "Background Execution",
        53: "Camera",
        54: "Microphone",
        55: "Location",
        56: "NFC",
        57: "Fingerprint",
        58: "Bluetooth",
        59: "SMS",
        61: "Google Cloud Messaging",
        62: "Maps",
        63: "Networking",
        64: "Telephony",
        65: "Photos",
        66: "In-App Purchases",
        67: "Device Administrator",
        68: "Camera Delegation",
        69: "Sensors",
        70: "USB Devices",
        71: "Geofencing",
        72: "Health Data",
        73: "Infrared LED",
        74: "Audio",
        75: "Payment Services",
        76: "Secure RNG",
        77: "Keystore",
    }

    FUNCTIONALITY_RULE_ID_MAP = {
        "android.background.execution.present": "Background Execution",
        "android.camera.usage.present": "Camera",
        "android.microphone.usage.present": "Microphone",
        "android.location.services.present": "Location",
        "android.maps.usage.present": "Maps",
        "android.networking.usage.present": "Networking",
        "android.nfc.usage.present": "NFC",
        "android.fingerprint.usage.present": "Fingerprint",
        "android.bluetooth.usage.present": "Bluetooth",
        "android.sms.usage.present": "SMS",
        "android.in_app_purchases.usage.present": "In-App Purchases",
        "android.device.administrator.usage.present": "Device Administrator",
        "android.camera.delegation.usage.present": "Camera Delegation",
        "android.sensors.usage.present": "Sensors",
        "android.usb.devices.usage.present": "USB Devices",
        "android.geofencing.usage.present": "Geofencing",
        "android.health.data.usage.present": "Health Data",
        "android.infrared.led.usage.present": "Infrared LED",
        "android.audio.usage.present": "Audio",
        "android.payment.services.usage.present": "Payment Services",
        "android.secure.rng.usage.present": "Secure RNG",
        "android.keystore.usage.present": "Keystore",
        "android.telephony.usage.present": "Telephony",
        "android.contacts.usage.present": "Contacts",
        "android.calendar.usage.present": "Calendar",
        "android.photos.usage.present": "Photos",
        "android.push.messaging.present": "Google Cloud Messaging",
    }

    FUNCTIONALITY_PERMISSION_MAP = {
        "Background Execution": {
            "android.permission.FOREGROUND_SERVICE",
            "android.permission.FOREGROUND_SERVICE_CONNECTED_DEVICE",
            "android.permission.RECEIVE_BOOT_COMPLETED",
        },
        "Camera": {
            "android.permission.CAMERA",
        },
        "Microphone": {
            "android.permission.RECORD_AUDIO",
        },
        "NFC": {
            "android.permission.NFC",
        },
        "Fingerprint": {
            "android.permission.USE_BIOMETRIC",
            "android.permission.USE_FINGERPRINT",
        },
        "Bluetooth": {
            "android.permission.BLUETOOTH",
            "android.permission.BLUETOOTH_ADMIN",
            "android.permission.BLUETOOTH_ADVERTISE",
            "android.permission.BLUETOOTH_CONNECT",
            "android.permission.BLUETOOTH_SCAN",
        },
        "SMS": {
            "android.permission.SEND_SMS",
            "android.permission.READ_SMS",
            "android.permission.RECEIVE_SMS",
            "android.permission.RECEIVE_MMS",
            "android.permission.RECEIVE_WAP_PUSH",
        },
        "Telephony": {
            "android.permission.ANSWER_PHONE_CALLS",
            "android.permission.CALL_PHONE",
            "android.permission.PROCESS_OUTGOING_CALLS",
            "android.permission.READ_CALL_LOG",
            "android.permission.READ_PHONE_NUMBERS",
            "android.permission.READ_PHONE_STATE",
            "android.permission.WRITE_CALL_LOG",
        },
        "Contacts": {
            "android.permission.READ_CONTACTS",
            "android.permission.WRITE_CONTACTS",
            "android.permission.GET_ACCOUNTS",
        },
        "Calendar": {
            "android.permission.READ_CALENDAR",
            "android.permission.WRITE_CALENDAR",
        },
        "Photos": {
            "android.permission.READ_EXTERNAL_STORAGE",
            "android.permission.READ_MEDIA_IMAGES",
            "android.permission.READ_MEDIA_VISUAL_USER_SELECTED",
            "android.permission.WRITE_EXTERNAL_STORAGE",
        },
        "Sensors": {
            "android.permission.BODY_SENSORS",
            "android.permission.BODY_SENSORS_BACKGROUND",
        },
    }

    FUNCTIONALITY_EXPLANATION_LABELS = {
        "Audio": "audio",
        "Background Execution": "background execution",
        "Location": "location",
        "Contacts": "contacts",
        "Geofencing": "geofencing",
        "Health Data": "health data",
        "Maps": "maps",
        "Networking": "networking",
        "Payment Services": "payment services",
        "SMS": "SMS",
        "Secure RNG": "secure RNG",
        "Bluetooth": "Bluetooth",
        "Camera": "camera",
        "Camera Delegation": "camera delegation",
        "Calendar": "calendar",
        "Device Administrator": "device administrator",
        "Fingerprint": "fingerprint",
        "Google Cloud Messaging": "Google Cloud Messaging",
        "Infrared LED": "infrared LED",
        "In-App Purchases": "in-app purchases",
        "Keystore": "keystore",
        "Microphone": "microphone",
        "NFC": "NFC",
        "Photos": "photo",
        "Sensors": "sensor",
        "Telephony": "telephony",
        "USB Devices": "USB device",
    }

    def extract_sections(self, loaded_outputs: dict[str, Any]) -> dict[str, Any]:
        return {
            "app_info": self._build_app_info(loaded_outputs),
            "app_components": self._build_app_components(loaded_outputs),
            "certificate": self._build_certificate(loaded_outputs),
            "file_info": self._build_file_info(loaded_outputs),
            "permissions": self._build_permissions(loaded_outputs),
            "functionality": self._build_functionality(loaded_outputs),
            "network_evidence": self._build_network_evidence(loaded_outputs),
            "storage_evidence": self._build_storage_evidence(loaded_outputs),
            "deep_links": self._build_deep_links(loaded_outputs),
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
                    "general_description": self._permission_description(name, declared_permissions),
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

    def _build_network_evidence(self, loaded_outputs: dict[str, Any]) -> dict[str, Any]:
        network_security = loaded_outputs.get("apktool_network_security_config") or {}
        aapt2_application = loaded_outputs.get("aapt2_application") or {}
        aapt2_posture = loaded_outputs.get("aapt2_manifest_security_posture") or {}

        domains = network_security.get("domains") or []
        provenance = network_security.get("provenance") or {}
        provenance_path = self._first_non_empty(provenance.get("path"), provenance.get("source"))
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

        return {
            "allows_cleartext_traffic_for_all_domains": {
                "present": bool(cleartext_present),
                "evidence": provenance_path or self._first_non_empty(network_security.get("policy_source")),
            },
            "contains_hostname_verifier_accepts_all": {
                "present": None,
                "evidence": "",
            },
            "contains_x509_trust_manager_accepts_all": {
                "present": None,
                "evidence": "",
            },
            "does_not_perform_certificate_pinning": {
                "present": missing_certificate_pinning,
                "evidence": provenance_path or self._first_non_empty(network_security.get("reference")),
            },
            "opens_listening_port": {
                "present": None,
                "evidence": "",
            },
            "sensitive_cookies_lack_security_attributes": {
                "present": None,
                "evidence": "",
            },
            "unnecessary_information_transmitted": {
                "present": None,
                "evidence": "",
            },
            "sensitive_information_unencrypted_in_transit": {
                "present": None,
                "evidence": "",
            },
            "password_not_hashed_in_transit": {
                "present": None,
                "evidence": "",
            },
            "weak_certificate_validation_enables_mitm": {
                "present": user_installed_ca_present,
                "evidence": provenance_path or self._first_non_empty(network_security.get("reference")),
            },
            "manifest_cleartext_traffic_permitted": self._coerce_true(
                aapt2_posture.get("cleartext_traffic_permitted")
            )
            if aapt2_posture
            else self._coerce_bool_like(aapt2_application.get("uses_cleartext_traffic")),
        }

    def _build_deep_links(self, loaded_outputs: dict[str, Any]) -> dict[str, Any]:
        apktool_deep_links = loaded_outputs.get("apktool_deep_links") or {}
        deep_links = apktool_deep_links.get("deep_links")
        if isinstance(deep_links, list):
            return {"deep_links": deep_links}
        return {"deep_links": []}

    def _build_storage_evidence(self, loaded_outputs: dict[str, Any]) -> dict[str, Any]:
        aapt2_permissions = loaded_outputs.get("aapt2_permissions") or {}
        androguard_api_calls = loaded_outputs.get("androguard_api_calls") or {}

        declared_permissions = {
            self._first_non_empty(permission.get("name"))
            for permission in aapt2_permissions.get("permissions") or []
        }
        declared_permissions.discard("")

        external_storage_permissions = sorted(
            permission
            for permission in declared_permissions
            if permission in self.EXTERNAL_STORAGE_PERMISSIONS
        )

        api_call_items = list(androguard_api_calls.get("items") or [])
        external_storage_callers = self._matching_api_call_sites(
            api_call_items,
            lambda item: "externalstorage" in self._api_call_signature(item).replace("_", "").lower(),
        )
        shared_preferences_callers = self._matching_api_call_sites(
            api_call_items,
            lambda item: self._api_call_method_name(item) == "getSharedPreferences",
        )
        credential_storage_callers = [
            caller
            for caller in shared_preferences_callers
            if self.STORAGE_CREDENTIAL_HINT_PATTERN.search(caller)
        ]

        accesses_external_storage_evidence = self._dedupe_preserve_order(
            [*external_storage_permissions, *external_storage_callers]
        )
        keystore_present = self._functionality_present(loaded_outputs, "Keystore")

        authentication_credentials_present = None
        if credential_storage_callers and not keystore_present:
            authentication_credentials_present = True

        return {
            "accesses_external_storage": {
                "present": bool(accesses_external_storage_evidence),
                "evidence": ", ".join(accesses_external_storage_evidence),
            },
            "authentication_credentials_not_protected_with_android_keystore": {
                "present": authentication_credentials_present,
                "evidence": ", ".join(self._dedupe_preserve_order(credential_storage_callers)),
            },
            "sensitive_information_stored_in_world_readable_or_writable_file_in_internal_storage": {
                "present": None,
                "evidence": "",
            },
            "sensitive_information_stored_in_external_storage": {
                "present": None,
                "evidence": "",
            },
            "does_not_prevent_screen_capture_of_sensitive_information": {
                "present": None,
                "evidence": "",
            },
        }

    def _build_hardcoded_values(self, loaded_outputs: dict[str, Any]) -> dict[str, Any]:
        apktool_secrets_endpoints = loaded_outputs.get("apktool_secrets_endpoints") or {}
        strings_outputs = loaded_outputs.get("strings_outputs") or {}

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
                if self._looks_like_secret_label(value):
                    continue
                location = self._format_provenance_location(item.get("provenance") or {})
                dedupe_key = (value, location)
                if dedupe_key in seen_secrets:
                    continue
                seen_secrets.add(dedupe_key)
                secrets.append({"value": value, "location": location})

        for source_name, content in strings_outputs.items():
            for line_number, line in enumerate(content.splitlines(), start=1):
                for match in self.ENCODED_SECRET_PATTERN.finditer(line):
                    value = match.group(0)
                    if not self._looks_like_encoded_secret(value):
                        continue
                    location = f"strings/{source_name}:{line_number}"
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
    def _coerce_true(value: object) -> bool:
        return str(value or "").strip().lower() == "true"

    @staticmethod
    def _coerce_bool_like(value: object) -> bool | None:
        text = str(value or "").strip().lower()
        if text in {"true", "1", "yes"}:
            return True
        if text in {"false", "0", "no"}:
            return False
        return None

    def _build_functionality(self, loaded_outputs: dict[str, Any]) -> dict[str, dict[str, Any]]:
        opengrep = loaded_outputs.get("opengrep") or {}
        aapt2_permissions = loaded_outputs.get("aapt2_permissions") or {}
        functionality = {
            key: {
                "present": False,
                "explanation": "",
            }
            for key in self.FUNCTIONALITY_KEYS
        }

        declared_permissions = {
            self._first_non_empty(permission.get("name")) for permission in aapt2_permissions.get("permissions") or []
        }
        declared_permissions.discard("")

        permission_evidence: dict[str, list[str]] = {}
        opengrep_evidence: dict[str, str] = {}

        for capability, permission_names in self.FUNCTIONALITY_PERMISSION_MAP.items():
            matched_permissions = sorted(permission_names.intersection(declared_permissions))
            if not matched_permissions:
                continue

            permission_evidence[capability] = matched_permissions

        for result in opengrep.get("results") or []:
            capability = self._functionality_name_for_result(result)
            if not capability or capability not in functionality:
                continue

            opengrep_evidence.setdefault(capability, self._functionality_explanation_for_result(result))

        for capability in self.FUNCTIONALITY_KEYS:
            matched_permissions = permission_evidence.get(capability, [])
            opengrep_explanation = opengrep_evidence.get(capability, "")

            if not matched_permissions and not opengrep_explanation:
                continue

            functionality[capability]["present"] = True
            functionality[capability]["explanation"] = self._build_functionality_explanation(
                capability=capability,
                matched_permissions=matched_permissions,
                opengrep_explanation=opengrep_explanation,
            )

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
        return sum(
            1
            for component in components
            if component.get("exported") is True
            or (
                component.get("exported") is None
                and bool(component.get("has_intent_filters"))
            )
        )

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

    def _permission_description(
        self,
        permission_name: str,
        declared_permissions: dict[str, str],
    ) -> str:
        description = self.ANDROID_PERMISSION_DESCRIPTIONS.get(permission_name)
        if description:
            return description

        declared_description = declared_permissions.get(permission_name, "")
        if declared_description:
            return declared_description

        suffix = permission_name.rsplit(".", 1)[-1].strip()
        if not suffix:
            return ""
        readable = suffix.replace("_", " ").lower()
        return readable[:1].upper() + readable[1:] + "."

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
        rule_id = str(result.get("check_id", "")).strip()
        if rule_id in self.FUNCTIONALITY_RULE_ID_MAP:
            return self.FUNCTIONALITY_RULE_ID_MAP[rule_id]

        metadata = ((result.get("extra") or {}).get("metadata") or {}).get("appcritiq") or {}

        check_id = metadata.get("check_id")
        title = str(metadata.get("title", "")).strip().lower()
        if isinstance(check_id, int):
            if check_id == 60:
                if "contact" in title:
                    return "Contacts"
                if "calendar" in title:
                    return "Calendar"
            if check_id in self.FUNCTIONALITY_CHECK_ID_MAP:
                return self.FUNCTIONALITY_CHECK_ID_MAP[check_id]

        if "background execution" in title:
            return "Background Execution"
        if "camera" in title:
            return "Camera"
        if "microphone" in title:
            return "Microphone"
        if "nfc" in title:
            return "NFC"
        if "bluetooth" in title:
            return "Bluetooth"
        if "contact" in title:
            return "Contacts"
        if "calendar" in title:
            return "Calendar"
        if "push notification" in title or "google cloud messaging" in title:
            return "Google Cloud Messaging"
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
    def _build_functionality_explanation(
        capability: str,
        matched_permissions: list[str],
        opengrep_explanation: str,
    ) -> str:
        permission_explanation = AndroidBinaryScanDetailExtractor._permission_based_functionality_explanation(
            capability=capability,
            permission_names=matched_permissions,
        )

        if opengrep_explanation and permission_explanation:
            return f"{opengrep_explanation} The app also declares {permission_explanation}"
        if opengrep_explanation:
            return opengrep_explanation
        return permission_explanation

    @staticmethod
    def _permission_based_functionality_explanation(capability: str, permission_names: list[str]) -> str:
        if not permission_names:
            return ""
        capability_label = AndroidBinaryScanDetailExtractor.FUNCTIONALITY_EXPLANATION_LABELS.get(
            capability,
            capability.lower(),
        )
        if len(permission_names) == 1:
            return f"permission {permission_names[0]}, which may indicate {capability_label} functionality."
        return f"permissions {', '.join(permission_names)}, which may indicate {capability_label} functionality."

    def _functionality_present(self, loaded_outputs: dict[str, Any], capability: str) -> bool:
        functionality = self._build_functionality(loaded_outputs)
        details = functionality.get(capability) or {}
        return bool(details.get("present"))

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

    def _matching_api_call_sites(
        self,
        api_calls: list[dict[str, Any]],
        predicate: Any,
    ) -> list[str]:
        callers: list[str] = []
        for item in api_calls:
            if not isinstance(item, dict) or not predicate(item):
                continue
            caller = item.get("caller") or {}
            signature = self._first_non_empty(caller.get("signature"))
            if signature:
                callers.append(signature)
        return self._dedupe_preserve_order(callers)

    def _api_call_method_name(self, item: dict[str, Any]) -> str:
        callee = item.get("callee") or {}
        return self._first_non_empty(callee.get("method_name"))

    def _api_call_signature(self, item: dict[str, Any]) -> str:
        callee = item.get("callee") or {}
        return self._first_non_empty(
            callee.get("signature"),
            callee.get("class_name"),
            callee.get("method_name"),
        )

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
