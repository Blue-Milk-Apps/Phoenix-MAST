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
    PASSWORD_HINT_PATTERN = re.compile(
        r"(?i)(?:passw(?:or)?d|passwd|pwd|newpassword|passcode|credential|login|auth)"
    )
    SENSITIVE_LOG_VALUE_PATTERN = re.compile(
        r"(?i)(?:passw(?:or)?d|passwd|pwd|token|secret|session|credential|pin|phonenumber|account)"
    )
    FLAG_SECURE_PATTERN = re.compile(r"(?i)\bflag_secure\b")
    WORLD_MODE_PATTERN = re.compile(r"(?i)mode_world_(?:readable|writable)")
    COOKIE_PATTERN = re.compile(r"(?i)\bcookie\b")
    COOKIE_SECURITY_ATTR_PATTERN = re.compile(r"(?i)\b(?:secure|httponly|samesite)\b")
    HTTP_URL_PATTERN = re.compile(r"(?i)\bhttp://[^\s'\"<>]+")
    ROOT_DETECTION_PATTERN = re.compile(r"(?i)(?:\bsu\b|busybox|supersu|magisk|test-keys|rootbeer|isrooted|rootcheck)")
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
    SENSITIVE_UI_HINT_PATTERN = re.compile(
        r"(?i)(?:login|logon|signin|signup|password|passcode|pin|account|transfer|statement|payment|auth|profile)"
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
            "application": self._build_application(loaded_outputs),
            "app_components": self._build_app_components(loaded_outputs),
            "certificate": self._build_certificate(loaded_outputs),
            "code_evidence": self._build_code_evidence(loaded_outputs),
            "file_info": self._build_file_info(loaded_outputs),
            "permissions": self._build_permissions(loaded_outputs),
            "functionality": self._build_functionality(loaded_outputs),
            "network_evidence": self._build_network_evidence(loaded_outputs),
            "resilience_evidence": self._build_resilience_evidence(loaded_outputs),
            "storage_evidence": self._build_storage_evidence(loaded_outputs),
            "deep_links": self._build_deep_links(loaded_outputs),
            "hardcoded_values": self._build_hardcoded_values(loaded_outputs),
            "endpoints": self._build_endpoints(loaded_outputs),
        }

    def _build_app_info(self, loaded_outputs: dict[str, Any]) -> dict[str, str]:
        androguard_metadata = loaded_outputs.get("androguard_metadata") or {}
        aapt2_identity = loaded_outputs.get("aapt2_identity") or {}
        apktool_manifest_summary = loaded_outputs.get("apktool_manifest_summary") or {}
        manifest_application = apktool_manifest_summary.get("application") or {}

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
            "debuggable": self._first_non_empty(
                manifest_application.get("debuggable"),
            ),
            "allow_backup": self._first_non_empty(
                manifest_application.get("allow_backup"),
            ),
            "app_store_id": "",
            "developer": "",
            "categories": "",
            "trackers_detected": "",
        }

    def _build_application(self, loaded_outputs: dict[str, Any]) -> dict[str, Any]:
        aapt2_application = loaded_outputs.get("aapt2_application") or {}
        apktool_manifest_summary = loaded_outputs.get("apktool_manifest_summary") or {}
        manifest_application = apktool_manifest_summary.get("application") or {}

        return {
            "debuggable": self._first_non_empty(
                manifest_application.get("debuggable"),
                aapt2_application.get("debuggable"),
            ),
            "allow_backup": self._first_non_empty(
                manifest_application.get("allow_backup"),
                aapt2_application.get("allow_backup"),
            ),
            "uses_cleartext_traffic": self._first_non_empty(
                manifest_application.get("uses_cleartext_traffic"),
                aapt2_application.get("uses_cleartext_traffic"),
            ),
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
        androguard_api_calls = loaded_outputs.get("androguard_api_calls") or {}
        hardcoded_values = self._build_hardcoded_values(loaded_outputs)
        package_prefix = self._app_package_prefix(loaded_outputs)

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

        password_not_hashed_in_transit = self._derive_password_not_hashed_in_transit(
            list(androguard_api_calls.get("items") or [])
        )
        api_call_items = list(androguard_api_calls.get("items") or [])
        hostname_verifier_hits = self._matching_api_call_sites(
            api_call_items,
            lambda item: self._caller_matches_package(item, package_prefix)
            and (
                "allow_all_hostname_verifier" in self._api_call_signature(item).lower()
                or "sethostnameverifier" in self._api_call_signature(item).lower()
            ),
        )
        trust_manager_hits = self._matching_api_call_sites(
            api_call_items,
            lambda item: self._caller_matches_package(item, package_prefix)
            and "checkservertrusted" in self._api_call_caller_signature(item).lower(),
        )
        listening_port_hits = self._matching_api_call_sites(
            api_call_items,
            lambda item: self._caller_matches_package(item, package_prefix)
            and any(
                token in self._api_call_signature(item).lower()
                for token in ("serversocket", "localserversocket", "datagramsocket; bind")
            ),
        )
        cookie_insecurity = self._detect_cookie_security_issue(loaded_outputs, package_prefix)
        unnecessary_info = self._detect_unnecessary_information_transmission(
            loaded_outputs,
            package_prefix,
        )
        unencrypted_transit = self._detect_unencrypted_transit_issue(
            loaded_outputs,
            hardcoded_values,
            cleartext_present=bool(cleartext_present),
            password_not_hashed_in_transit=password_not_hashed_in_transit,
        )

        return {
            "allows_cleartext_traffic_for_all_domains": {
                "present": bool(cleartext_present),
                "evidence": provenance_path or self._first_non_empty(network_security.get("policy_source")),
            },
            "contains_hostname_verifier_accepts_all": {
                "present": True if hostname_verifier_hits else None,
                "evidence": ", ".join(hostname_verifier_hits[:5]) if hostname_verifier_hits else "",
            },
            "contains_x509_trust_manager_accepts_all": {
                "present": True if trust_manager_hits else None,
                "evidence": ", ".join(trust_manager_hits[:5]) if trust_manager_hits else "",
            },
            "does_not_perform_certificate_pinning": {
                "present": missing_certificate_pinning,
                "evidence": provenance_path or self._first_non_empty(network_security.get("reference")),
            },
            "opens_listening_port": {
                "present": bool(listening_port_hits) if api_call_items else None,
                "evidence": ", ".join(listening_port_hits[:5]) if listening_port_hits else "",
            },
            "sensitive_cookies_lack_security_attributes": cookie_insecurity,
            "unnecessary_information_transmitted": unnecessary_info,
            "sensitive_information_unencrypted_in_transit": unencrypted_transit,
            "password_not_hashed_in_transit": {
                "present": password_not_hashed_in_transit["present"],
                "evidence": password_not_hashed_in_transit["evidence"],
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

        screen_capture_protection = self._detect_screen_capture_protection(loaded_outputs)
        world_readable_internal = self._detect_world_readable_internal_storage(api_call_items)
        sensitive_external_storage = self._detect_sensitive_external_storage(
            external_storage_callers,
            hardcoded_values=self._build_hardcoded_values(loaded_outputs),
        )

        return {
            "accesses_external_storage": {
                "present": bool(accesses_external_storage_evidence),
                "evidence": ", ".join(accesses_external_storage_evidence),
            },
            "authentication_credentials_not_protected_with_android_keystore": {
                "present": authentication_credentials_present,
                "evidence": ", ".join(self._dedupe_preserve_order(credential_storage_callers)),
            },
            "sensitive_information_stored_in_world_readable_or_writable_file_in_internal_storage": (
                world_readable_internal
            ),
            "sensitive_information_stored_in_external_storage": sensitive_external_storage,
            "does_not_prevent_screen_capture_of_sensitive_information": screen_capture_protection,
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

    def _build_resilience_evidence(self, loaded_outputs: dict[str, Any]) -> dict[str, Any]:
        package_prefix = self._app_package_prefix(loaded_outputs)
        api_calls = list(((loaded_outputs.get("androguard_api_calls") or {}).get("items") or []))
        root_detection_hits = self._detect_root_detection_signals(
            loaded_outputs,
            package_prefix,
            api_calls,
        )
        biometric_bypass = self._detect_biometric_bypass_possible(
            loaded_outputs,
            package_prefix,
            api_calls,
        )

        return {
            "root_detection_missing": {
                "present": not bool(root_detection_hits),
                "evidence": (
                    "no_root_detection_signals_found"
                    if not root_detection_hits
                    else ", ".join(root_detection_hits[:5])
                ),
                "details": root_detection_hits[:10] if root_detection_hits else [],
            },
            "biometric_local_authentication_bypass_possible": biometric_bypass,
        }

    def _build_code_evidence(self, loaded_outputs: dict[str, Any]) -> dict[str, Any]:
        app_components = self._build_app_components(loaded_outputs)
        application = self._build_application(loaded_outputs)
        app_info = self._build_app_info(loaded_outputs)
        hardcoded_values = self._build_hardcoded_values(loaded_outputs)

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

        reflection_callers = self._matching_api_call_sites(
            api_calls,
            lambda item: "reflect" in self._api_call_signature(item).lower(),
        )
        runtime_exec_callers = self._matching_api_call_sites(
            api_calls,
            lambda item: "runtime; exec" in self._api_call_signature(item).lower(),
        )
        provider_update_callers = self._matching_api_call_sites(
            api_calls,
            lambda item: "providerinstaller" in self._api_call_caller_signature(item).lower()
            or "providerinstaller" in self._api_call_signature(item).lower(),
        )

        identifier_callers = self._matching_api_call_sites(
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

        sql_callers = self._matching_api_call_sites(
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

        clipboard_callers = self._matching_api_call_sites(
            api_calls,
            lambda item: "clipboard" in self._api_call_signature(item).lower()
            or "setprimaryclip" in self._api_call_signature(item).lower(),
        )

        code_indicator_values = [self._first_non_empty(item.get("value")) for item in code_indicator_items]
        code_indicator_locations = [
            self._format_provenance_location(item.get("provenance") or {})
            for item in code_indicator_items
        ]
        report_api_counts = dict(androguard_report_summary.get("api_category_counts") or {})

        password_secret_hits = [
            secret for secret in hardcoded_values.get("secrets") or []
            if self.PASSWORD_HINT_PATTERN.search(
                f"{secret.get('value', '')} {secret.get('location', '')}"
            )
        ]

        crypto_secret_hits = [
            secret for secret in hardcoded_values.get("secrets") or []
            if any(
                token in f"{secret.get('value', '')} {secret.get('location', '')}".lower()
                for token in ("key", "crypto", "cipher", "aes", "rsa", "des", "blowfish")
            )
        ]

        source_package = self._first_non_empty(
            app_info.get("package_name"),
            aapt2_identity.get("package_name"),
        )
        readable_app_classes = self._readable_app_class_names(
            source_package,
            loaded_outputs,
            runtime_exec_callers,
        )

        native_abis = list(aapt2_identity.get("native_abis") or [])
        native_abi_presence = self._coerce_bool_like(aapt2_posture.get("native_abi_presence"))

        reflection_present = bool(reflection_callers) or any(
            "reflection" in str(finding.get("id", "")).lower()
            or "reflection" in str(finding.get("title", "")).lower()
            for finding in finding_items
        ) or int(report_api_counts.get("reflection") or 0) > 0

        sql_injection_present = any("sql injection" in str(finding.get("title", "")).lower() for finding in finding_items)
        uses_provider_update = bool(provider_update_callers)
        root_access_present = bool(runtime_exec_callers)
        app_debuggable = self._coerce_bool_like(application.get("debuggable"))
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

        return {
            "accesses_unique_identifiers": self._code_evidence_entry(
                present=accesses_unique_identifiers,
                evidence=", ".join(identifier_callers[:5]) if identifier_callers else "no_identifier_api_hits",
                details=identifier_callers[:10],
            ),
            "activities_accessible_to_other_apps": self._component_access_evidence(
                app_components,
                "exported_activities",
                "activities",
            ),
            "app_is_debuggable": self._code_evidence_entry(
                present=app_debuggable,
                evidence=f"debuggable={str(app_debuggable).lower()}" if app_debuggable is not None else "",
            ),
            "contains_hard_coded_cryptographic_key": self._code_evidence_entry(
                present=bool(crypto_secret_hits),
                evidence=", ".join(
                    self._first_non_empty(secret.get("location"), secret.get("value"))
                    for secret in crypto_secret_hits[:5]
                ) or "no_crypto_key_hits",
                details=crypto_secret_hits[:10],
            ),
            "contains_native_code": self._code_evidence_entry(
                present=bool(native_abis) or native_abi_presence is True,
                evidence=(
                    f"native_abis={','.join(native_abis)}"
                    if native_abis
                    else f"native_abi_presence={str(native_abi_presence).lower()}"
                ),
                details=native_abis,
            ),
            "contains_potential_hard_coded_password": self._code_evidence_entry(
                present=bool(password_secret_hits),
                evidence=", ".join(
                    self._first_non_empty(secret.get("location"), secret.get("value"))
                    for secret in password_secret_hits[:5]
                ) or "no_password_hits",
                details=password_secret_hits[:10],
            ),
            "contains_potential_sql_injection": self._code_evidence_entry(
                present=sql_injection_present,
                evidence=", ".join(sql_callers[:5]) if sql_injection_present else "no_sql_injection_finding",
                details=sql_callers[:10],
            ),
            "contains_reflection_code": self._code_evidence_entry(
                present=reflection_present,
                evidence=", ".join(
                    self._dedupe_preserve_order(
                        [*reflection_callers[:3], *[loc for loc in code_indicator_locations[:10] if loc]]
                    )[:5]
                )
                or f"reflection_count={int(report_api_counts.get('reflection') or 0)}",
                details=reflection_callers[:10],
            ),
            "creates_blowfish_key_with_weak_length": self._code_evidence_entry(
                present=weak_blowfish_evidence.get("present"),
                evidence=weak_blowfish_evidence.get("evidence", ""),
                details=weak_blowfish_evidence.get("details"),
            ),
            "creates_rsa_keys_with_weak_modulus_length": self._code_evidence_entry(
                present=weak_rsa_evidence.get("present"),
                evidence=weak_rsa_evidence.get("evidence", ""),
                details=weak_rsa_evidence.get("details"),
            ),
            "does_not_update_security_provider": self._code_evidence_entry(
                present=not uses_provider_update,
                evidence=(
                    ", ".join(provider_update_callers[:5])
                    if provider_update_callers
                    else "no_security_provider_update_calls"
                ),
                details=provider_update_callers[:10],
            ),
            "receivers_accessible_to_other_apps": self._component_access_evidence(
                app_components,
                "exported_receivers",
                "receivers",
            ),
            "requests_root_access": self._code_evidence_entry(
                present=root_access_present,
                evidence=", ".join(runtime_exec_callers[:5]) if runtime_exec_callers else "no_su_runtime_exec_hits",
                details=runtime_exec_callers[:10],
            ),
            "services_accessible_to_other_apps": self._component_access_evidence(
                app_components,
                "exported_services",
                "services",
            ),
            "sms_cve_2014_8610": self._code_evidence_entry(
                present=not sms_permission_present,
                evidence=(
                    "android.permission.SEND_SMS missing"
                    if not sms_permission_present
                    else "android.permission.SEND_SMS declared"
                ),
            ),
            "source_code_is_not_obfuscated": self._code_evidence_entry(
                present=source_not_obfuscated,
                evidence=", ".join(readable_app_classes[:5]) if readable_app_classes else "no_readable_app_class_names",
                details=readable_app_classes[:10],
            ),
            "uses_sha1_hashing_algorithm": self._code_evidence_entry(
                present=sha1_evidence.get("present"),
                evidence=sha1_evidence.get("evidence", ""),
                details=sha1_evidence.get("details"),
            ),
            "weakly_configured_xml_parser": self._code_evidence_entry(
                present=weak_xml_evidence.get("present"),
                evidence=weak_xml_evidence.get("evidence", ""),
                details=weak_xml_evidence.get("details"),
            ),
            "writes_sensitive_information_to_system_log": self._code_evidence_entry(
                present=sensitive_log_evidence.get("present"),
                evidence=sensitive_log_evidence.get("evidence", ""),
                details=sensitive_log_evidence.get("details"),
            ),
            "uses_spoofable_values_for_authentication": self._code_evidence_entry(
                present=spoofable_auth_evidence.get("present"),
                evidence=spoofable_auth_evidence.get("evidence", ""),
                details=spoofable_auth_evidence.get("details"),
            ),
            "copies_sensitive_information_into_clipboard_without_user_consent": self._code_evidence_entry(
                present=bool(clipboard_callers),
                evidence=", ".join(clipboard_callers[:5]) if clipboard_callers else "no_clipboard_hits",
                details=clipboard_callers[:10],
            ),
        }

    def _component_access_evidence(
        self,
        app_components: dict[str, int],
        exported_key: str,
        label: str,
    ) -> dict[str, Any]:
        exported_count = int(app_components.get(exported_key) or 0)
        return self._code_evidence_entry(
            present=exported_count > 0,
            evidence=f"{exported_key}={exported_count}",
            details=[f"{label}={int(app_components.get(label) or 0)}"],
        )

    @staticmethod
    def _code_evidence_entry(
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
        main_activity = self._first_non_empty(aapt2_identity.get("launchable_activity"))
        if main_activity:
            candidates.append(main_activity)

        androguard_components = loaded_outputs.get("androguard_components") or {}
        for component_type in ("activities", "services", "receivers", "providers"):
            for component in androguard_components.get(component_type) or []:
                if not isinstance(component, dict):
                    continue
                candidates.append(
                    self._first_non_empty(
                        component.get("name"),
                        component.get("class_name"),
                    )
                )

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

    def _summarize_code_indicators(self, artifact: dict[str, Any]) -> dict[str, Any]:
        items = artifact.get("items") or []
        category_counts: dict[str, int] = {}
        sample_values_by_category: dict[str, list[str]] = {}
        sample_locations_by_category: dict[str, list[str]] = {}

        for item in items:
            if not isinstance(item, dict):
                continue
            category = self._first_non_empty((item.get("context") or {}).get("category")) or "uncategorized"
            category_counts[category] = category_counts.get(category, 0) + 1

            value = self._first_non_empty(item.get("value"))
            if value:
                sample_values_by_category.setdefault(category, [])
                if value not in sample_values_by_category[category] and len(sample_values_by_category[category]) < 5:
                    sample_values_by_category[category].append(value)

            location = self._format_provenance_location(item.get("provenance") or {})
            if location:
                sample_locations_by_category.setdefault(category, [])
                if location not in sample_locations_by_category[category] and len(sample_locations_by_category[category]) < 5:
                    sample_locations_by_category[category].append(location)

        return {
            "item_count": len(items),
            "category_counts": category_counts,
            "sample_values_by_category": sample_values_by_category,
            "sample_locations_by_category": sample_locations_by_category,
        }

    def _summarize_findings(self, artifact: dict[str, Any]) -> dict[str, Any]:
        items = artifact.get("items") or []
        severity_counts: dict[str, int] = {}
        finding_ids: list[str] = []
        finding_titles: list[str] = []
        findings: list[dict[str, Any]] = []

        for item in items:
            if not isinstance(item, dict):
                continue

            severity = self._first_non_empty(item.get("severity")).lower()
            if severity:
                severity_counts[severity] = severity_counts.get(severity, 0) + 1

            finding_id = self._first_non_empty(item.get("id"))
            title = self._first_non_empty(item.get("title"))
            if finding_id and finding_id not in finding_ids:
                finding_ids.append(finding_id)
            if title and title not in finding_titles:
                finding_titles.append(title)

            evidence_callers: list[str] = []
            for evidence_item in item.get("evidence") or []:
                if not isinstance(evidence_item, dict):
                    continue
                caller_signature = self._first_non_empty(((evidence_item.get("caller") or {}).get("signature")))
                if caller_signature and caller_signature not in evidence_callers and len(evidence_callers) < 5:
                    evidence_callers.append(caller_signature)

            findings.append(
                {
                    "id": finding_id,
                    "title": title,
                    "severity": severity,
                    "confidence": self._first_non_empty(item.get("confidence")),
                    "sample_callers": evidence_callers,
                }
            )

        return {
            "item_count": len(items),
            "severity_counts": severity_counts,
            "finding_ids": finding_ids,
            "finding_titles": finding_titles,
            "findings": findings,
        }

    def _summarize_strings(self, artifact: dict[str, Any]) -> dict[str, Any]:
        items = artifact.get("items") or []
        category_counts: dict[str, int] = {}
        sample_values_by_category: dict[str, list[str]] = {}
        sample_xrefs_by_category: dict[str, list[str]] = {}

        for item in items:
            if not isinstance(item, dict):
                continue
            categories = [str(category).strip() for category in (item.get("categories") or []) if str(category).strip()]
            value = self._first_non_empty(item.get("value"))
            xrefs = item.get("xrefs") or []

            for category in categories or ["uncategorized"]:
                category_counts[category] = category_counts.get(category, 0) + 1
                if value:
                    sample_values_by_category.setdefault(category, [])
                    if value not in sample_values_by_category[category] and len(sample_values_by_category[category]) < 5:
                        sample_values_by_category[category].append(value)

                for xref in xrefs:
                    if not isinstance(xref, dict):
                        continue
                    signature = self._first_non_empty(xref.get("signature"))
                    if not signature:
                        continue
                    sample_xrefs_by_category.setdefault(category, [])
                    if signature not in sample_xrefs_by_category[category] and len(sample_xrefs_by_category[category]) < 5:
                        sample_xrefs_by_category[category].append(signature)

        return {
            "item_count": len(items),
            "category_counts": category_counts,
            "sample_values_by_category": sample_values_by_category,
            "sample_xrefs_by_category": sample_xrefs_by_category,
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
                "explanation": self._absent_functionality_explanation(key),
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
    def _absent_functionality_explanation(capability: str) -> str:
        capability_label = AndroidBinaryScanDetailExtractor.FUNCTIONALITY_EXPLANATION_LABELS.get(
            capability,
            capability.lower(),
        )
        return f"No permission or scan evidence indicated {capability_label} functionality."

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

    def _derive_password_not_hashed_in_transit(self, api_calls: list[dict[str, Any]]) -> dict[str, Any]:
        if not api_calls:
            return {"present": None, "evidence": ""}

        password_network_callers: list[str] = []
        hashed_password_callers: list[str] = []

        for item in api_calls:
            if not isinstance(item, dict):
                continue
            caller_signature = self._api_call_caller_signature(item)
            if not caller_signature or not self.PASSWORD_HINT_PATTERN.search(caller_signature):
                continue
            if self._is_network_api_call(item):
                password_network_callers.append(caller_signature)
            if self._is_hash_api_call(item):
                hashed_password_callers.append(caller_signature)

        password_network_callers = self._dedupe_preserve_order(password_network_callers)
        hashed_password_callers = self._dedupe_preserve_order(hashed_password_callers)
        unhashed_callers = [
            caller for caller in password_network_callers
            if caller not in set(hashed_password_callers)
        ]

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

    def _detect_screen_capture_protection(self, loaded_outputs: dict[str, Any]) -> dict[str, Any]:
        package_prefix = self._first_non_empty(
            ((loaded_outputs.get("aapt2_identity") or {}).get("package_name")),
            ((loaded_outputs.get("androguard_metadata") or {}).get("package")),
        ).replace(".", "/")
        api_calls = list(((loaded_outputs.get("androguard_api_calls") or {}).get("items") or []))
        strings_outputs = loaded_outputs.get("strings_outputs") or {}

        secure_flag_callers = self._matching_api_call_sites(
            api_calls,
            lambda item: self._caller_matches_package(item, package_prefix)
            and self._is_window_flag_api_call(item),
        )
        secure_flag_source_hits = self._matching_strings_output_sources(
            strings_outputs=strings_outputs,
            pattern=self.FLAG_SECURE_PATTERN,
            package_prefix=package_prefix,
        )
        sensitive_ui_classes = self._sensitive_ui_class_names(loaded_outputs, package_prefix)

        secure_hits = self._dedupe_preserve_order([*secure_flag_callers, *secure_flag_source_hits])
        if secure_hits:
            return {
                "present": False,
                "evidence": secure_hits[0],
                "details": secure_hits[:10],
            }

        if sensitive_ui_classes:
            listed = ", ".join(sensitive_ui_classes[:5])
            return {
                "present": True,
                "evidence": f"no FLAG_SECURE usage found in sensitive UI classes: {listed}",
                "details": sensitive_ui_classes[:10],
            }

        return {
            "present": None,
            "evidence": "",
        }

    def _detect_cookie_security_issue(self, loaded_outputs: dict[str, Any], package_prefix: str) -> dict[str, Any]:
        cookie_hits = self._matching_string_xrefs(
            loaded_outputs=loaded_outputs,
            value_predicate=lambda value: self.COOKIE_PATTERN.search(value) is not None,
            xref_predicate=lambda signature: package_prefix in signature.replace(".", "/") if package_prefix else False,
        )
        cookie_attr_hits = self._matching_string_xrefs(
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
            self._matching_api_call_sites(
                api_calls,
                lambda item: self._caller_matches_package(item, package_prefix)
                and any(
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
        )
        network_callers = set(
            self._matching_api_call_sites(
                api_calls,
                lambda item: self._caller_matches_package(item, package_prefix)
                and self._is_network_api_call(item),
            )
        )
        overlapping = [caller for caller in identifier_callers if caller in network_callers]
        if overlapping:
            return {"present": True, "evidence": overlapping[0], "details": overlapping[:10]}
        if not identifier_callers:
            return {"present": False, "evidence": "no_unique_identifier_network_overlap"}
        return {"present": None, "evidence": ""}

    def _detect_unencrypted_transit_issue(
        self,
        loaded_outputs: dict[str, Any],
        hardcoded_values: dict[str, Any],
        *,
        cleartext_present: bool,
        password_not_hashed_in_transit: dict[str, Any],
    ) -> dict[str, Any]:
        urls = [str(item.get("url", "")).strip() for item in hardcoded_values.get("urls") or []]
        insecure_urls = [
            url for url in urls
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

    def _detect_world_readable_internal_storage(self, api_calls: list[dict[str, Any]]) -> dict[str, Any]:
        world_mode_hits = self._matching_api_call_sites(
            api_calls,
            lambda item: self.WORLD_MODE_PATTERN.search(self._api_call_signature(item)) is not None
            or self.WORLD_MODE_PATTERN.search(self._api_call_caller_signature(item)) is not None,
        )
        if world_mode_hits:
            return {"present": True, "evidence": world_mode_hits[0], "details": world_mode_hits[:10]}
        if api_calls:
            return {"present": False, "evidence": "no_world_readable_internal_storage_hits"}
        return {"present": None, "evidence": ""}

    def _detect_sensitive_external_storage(
        self,
        external_storage_callers: list[str],
        *,
        hardcoded_values: dict[str, Any],
    ) -> dict[str, Any]:
        sensitive_callers = [
            caller for caller in external_storage_callers
            if self.PASSWORD_HINT_PATTERN.search(caller) or self.SENSITIVE_UI_HINT_PATTERN.search(caller)
        ]
        if sensitive_callers:
            return {"present": True, "evidence": sensitive_callers[0], "details": sensitive_callers[:10]}
        secrets = hardcoded_values.get("secrets") or []
        external_secret_hits = [
            secret for secret in secrets
            if "external" in str(secret.get("location", "")).lower()
        ]
        if external_secret_hits:
            evidence = self._first_non_empty(
                external_secret_hits[0].get("location"),
                external_secret_hits[0].get("value"),
            )
            return {"present": True, "evidence": evidence, "details": external_secret_hits[:10]}
        if not external_storage_callers:
            return {"present": False, "evidence": "no_external_storage_sensitive_hits"}
        return {"present": None, "evidence": ""}

    def _detect_root_detection_signals(
        self,
        loaded_outputs: dict[str, Any],
        package_prefix: str,
        api_calls: list[dict[str, Any]],
    ) -> list[str]:
        api_hits = self._matching_api_call_sites(
            api_calls,
            lambda item: self._caller_matches_package(item, package_prefix)
            and self.ROOT_DETECTION_PATTERN.search(
                f"{self._api_call_signature(item)} {self._api_call_caller_signature(item)}"
            )
            is not None,
        )
        string_hits = self._matching_string_xrefs(
            loaded_outputs=loaded_outputs,
            value_predicate=lambda value: self.ROOT_DETECTION_PATTERN.search(value) is not None,
            xref_predicate=lambda signature: package_prefix in signature.replace(".", "/") if package_prefix else False,
        )
        return self._dedupe_preserve_order([*api_hits, *string_hits])

    def _detect_biometric_bypass_possible(
        self,
        loaded_outputs: dict[str, Any],
        package_prefix: str,
        api_calls: list[dict[str, Any]],
    ) -> dict[str, Any]:
        biometric_callers = self._matching_api_call_sites(
            api_calls,
            lambda item: self._caller_matches_package(item, package_prefix)
            and any(
                token in self._api_call_signature(item).lower()
                for token in ("biometricprompt", "fingerprintmanager", "fingerprint")
            ),
        )
        hardening_callers = self._matching_api_call_sites(
            api_calls,
            lambda item: self._caller_matches_package(item, package_prefix)
            and any(
                token in self._api_call_signature(item).lower()
                for token in (
                    "cryptoobject",
                    "setuserauthenticationrequired",
                    "keygenparameterspec",
                )
            ),
        )
        if biometric_callers and not hardening_callers:
            return {"present": True, "evidence": biometric_callers[0], "details": biometric_callers[:10]}
        if biometric_callers and hardening_callers:
            return {"present": False, "evidence": hardening_callers[0], "details": hardening_callers[:10]}
        return {"present": False, "evidence": "no_biometric_authentication_flow_detected"}

    def _detect_sha1_usage(
        self,
        loaded_outputs: dict[str, Any],
        package_prefix: str,
        api_calls: list[dict[str, Any]],
        code_indicator_items: list[dict[str, Any]],
    ) -> dict[str, Any]:
        crypto_callers = self._matching_api_call_sites(
            api_calls,
            lambda item: self._caller_matches_package(item, package_prefix)
            and (
                self._is_hash_api_call(item)
                or any(
                    token in self._api_call_signature(item).lower()
                    for token in ("messagedigest", "signature;", "mac;")
                )
            ),
        )
        sha1_xrefs = self._matching_string_xrefs(
            loaded_outputs=loaded_outputs,
            value_predicate=lambda value: self.SHA1_PATTERN.search(value) is not None,
            xref_predicate=lambda signature: package_prefix in signature.replace(".", "/") if package_prefix else False,
        )
        sha1_indicator_locations = self._matching_code_indicator_locations(
            code_indicator_items,
            package_prefix=package_prefix,
            value_predicate=lambda value: self.SHA1_PATTERN.search(value) is not None,
        )
        overlapping = [caller for caller in crypto_callers if caller in set(sha1_xrefs)]
        evidence_hits = self._dedupe_preserve_order([*overlapping, *sha1_indicator_locations, *sha1_xrefs])
        if evidence_hits:
            return {"present": True, "evidence": evidence_hits[0], "details": evidence_hits[:10]}
        if crypto_callers:
            return {"present": False, "evidence": "no_sha1_hits", "details": crypto_callers[:10]}
        return {"present": False, "evidence": "no_sha1_hits"}

    def _detect_weak_blowfish_key_length(
        self,
        loaded_outputs: dict[str, Any],
        package_prefix: str,
        api_calls: list[dict[str, Any]],
        code_indicator_items: list[dict[str, Any]],
    ) -> dict[str, Any]:
        crypto_callers = self._matching_api_call_sites(
            api_calls,
            lambda item: self._caller_matches_package(item, package_prefix)
            and any(
                token in self._api_call_signature(item).lower()
                for token in ("cipher;", "secretkeyspec", "keygenerator", "secretkeyfactory")
            ),
        )
        blowfish_xrefs = self._matching_string_xrefs(
            loaded_outputs=loaded_outputs,
            value_predicate=lambda value: self.BLOWFISH_PATTERN.search(value) is not None,
            xref_predicate=lambda signature: package_prefix in signature.replace(".", "/") if package_prefix else False,
        )
        weak_size_xrefs = self._matching_string_xrefs(
            loaded_outputs=loaded_outputs,
            value_predicate=lambda value: self.WEAK_BLOWFISH_KEY_BITS_PATTERN.search(value) is not None,
            xref_predicate=lambda signature: package_prefix in signature.replace(".", "/") if package_prefix else False,
        )
        weak_indicator_locations = self._matching_code_indicator_locations(
            code_indicator_items,
            package_prefix=package_prefix,
            value_predicate=lambda value: self.BLOWFISH_PATTERN.search(value) is not None
            and self.WEAK_BLOWFISH_KEY_BITS_PATTERN.search(value) is not None,
        )
        overlapping = [
            caller for caller in crypto_callers
            if caller in set(blowfish_xrefs) and caller in set(weak_size_xrefs)
        ]
        evidence_hits = self._dedupe_preserve_order([*overlapping, *weak_indicator_locations])
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
        rsa_callers = self._matching_api_call_sites(
            api_calls,
            lambda item: self._caller_matches_package(item, package_prefix)
            and any(
                token in self._api_call_signature(item).lower()
                for token in ("keypairgenerator", "rsakeygenparameterspec", "keyfactory", "rsapublickeyspec")
            ),
        )
        rsa_xrefs = self._matching_string_xrefs(
            loaded_outputs=loaded_outputs,
            value_predicate=lambda value: self.RSA_PATTERN.search(value) is not None,
            xref_predicate=lambda signature: package_prefix in signature.replace(".", "/") if package_prefix else False,
        )
        weak_size_xrefs = self._matching_string_xrefs(
            loaded_outputs=loaded_outputs,
            value_predicate=lambda value: self.WEAK_RSA_KEY_BITS_PATTERN.search(value) is not None,
            xref_predicate=lambda signature: package_prefix in signature.replace(".", "/") if package_prefix else False,
        )
        weak_indicator_locations = self._matching_code_indicator_locations(
            code_indicator_items,
            package_prefix=package_prefix,
            value_predicate=lambda value: self.RSA_PATTERN.search(value) is not None
            and self.WEAK_RSA_KEY_BITS_PATTERN.search(value) is not None,
        )
        overlapping = [
            caller for caller in rsa_callers
            if caller in set(rsa_xrefs) and caller in set(weak_size_xrefs)
        ]
        evidence_hits = self._dedupe_preserve_order([*overlapping, *weak_indicator_locations])
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
        parser_callers = self._matching_api_call_sites(
            api_calls,
            lambda item: self._caller_matches_package(item, package_prefix)
            and self.XML_PARSER_PATTERN.search(self._api_call_signature(item)) is not None,
        )
        weak_xrefs = self._matching_string_xrefs(
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
        evidence_hits = self._dedupe_preserve_order([*overlapping, *weak_indicator_locations, *weak_xrefs])
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
        log_callers = self._matching_api_call_sites(
            api_calls,
            lambda item: self._caller_matches_package(item, package_prefix)
            and "android/util/log" in self._api_call_signature(item).lower(),
        )
        if not log_callers:
            return {"present": False, "evidence": "no_sensitive_logging_hits"}

        sensitive_xrefs = self._matching_string_xrefs(
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
        identifier_callers = self._matching_api_call_sites(
            api_calls,
            lambda item: self._caller_matches_package(item, package_prefix)
            and self.SPOOFABLE_IDENTIFIER_PATTERN.search(self._api_call_signature(item)) is not None,
        )
        auth_xrefs = self._matching_string_xrefs(
            loaded_outputs=loaded_outputs,
            value_predicate=lambda value: self.AUTH_VALUE_PATTERN.search(value) is not None,
            xref_predicate=lambda signature: package_prefix in signature.replace(".", "/") if package_prefix else False,
        )
        network_callers = self._matching_api_call_sites(
            api_calls,
            lambda item: self._caller_matches_package(item, package_prefix)
            and self._is_network_api_call(item),
        )

        overlapping = [
            caller for caller in identifier_callers
            if caller in set(auth_xrefs) or caller in set(network_callers)
        ]
        if overlapping:
            return {"present": True, "evidence": overlapping[0], "details": overlapping[:10]}
        if identifier_callers:
            return {"present": False, "evidence": "no_spoofable_authentication_hits", "details": identifier_callers[:10]}
        return {"present": False, "evidence": "no_spoofable_authentication_hits"}

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

    def _api_call_caller_signature(self, item: dict[str, Any]) -> str:
        caller = item.get("caller") or {}
        return self._first_non_empty(
            caller.get("signature"),
            caller.get("class_name"),
            caller.get("method_name"),
        )

    def _caller_matches_package(self, item: dict[str, Any], package_prefix: str) -> bool:
        if not package_prefix:
            return False
        caller_signature = self._api_call_caller_signature(item)
        return package_prefix in caller_signature.replace(".", "/")

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
            value = self._first_non_empty(item.get("value"))
            if not value or not value_predicate(value):
                continue
            provenance = item.get("provenance") or {}
            path = self._first_non_empty(provenance.get("path"), provenance.get("source"))
            normalized_path = path.replace(".", "/")
            if normalized_package and normalized_package not in normalized_path:
                continue
            location = self._format_provenance_location(provenance)
            if location:
                matches.append(location)
        return self._dedupe_preserve_order(matches)

    def _is_window_flag_api_call(self, item: dict[str, Any]) -> bool:
        signature = self._api_call_signature(item).lower()
        method_name = self._api_call_method_name(item).lower()
        if method_name not in {"addflags", "setflags"}:
            return False
        return "android/view/window" in signature or "layoutparams" in signature

    def _matching_strings_output_sources(
        self,
        *,
        strings_outputs: dict[str, str],
        pattern: re.Pattern[str],
        package_prefix: str,
    ) -> list[str]:
        matches: list[str] = []
        for source_name, content in strings_outputs.items():
            if pattern.search(content or "") is None:
                continue
            normalized_source = source_name.replace(".", "/")
            if package_prefix and package_prefix not in normalized_source:
                continue
            matches.append(f"strings/{source_name}")
        return self._dedupe_preserve_order(matches)

    def _matching_string_xrefs(
        self,
        *,
        loaded_outputs: dict[str, Any],
        value_predicate: Any,
        xref_predicate: Any,
    ) -> list[str]:
        androguard_strings = loaded_outputs.get("androguard_strings") or {}
        matches: list[str] = []
        for item in androguard_strings.get("items") or []:
            if not isinstance(item, dict):
                continue
            value = self._first_non_empty(item.get("value"))
            if not value or not value_predicate(value):
                continue
            for xref in item.get("xrefs") or []:
                if not isinstance(xref, dict):
                    continue
                signature = self._first_non_empty(xref.get("signature"))
                if signature and xref_predicate(signature):
                    matches.append(signature)
        return self._dedupe_preserve_order(matches)

    def _app_package_prefix(self, loaded_outputs: dict[str, Any]) -> str:
        return self._first_non_empty(
            ((loaded_outputs.get("aapt2_identity") or {}).get("package_name")),
            ((loaded_outputs.get("androguard_metadata") or {}).get("package")),
        ).replace(".", "/")

    def _sensitive_ui_class_names(self, loaded_outputs: dict[str, Any], package_prefix: str) -> list[str]:
        candidates: list[str] = []
        aapt2_identity = loaded_outputs.get("aapt2_identity") or {}
        main_activity = self._first_non_empty(aapt2_identity.get("launchable_activity"))
        if main_activity:
            candidates.append(main_activity)

        androguard_components = loaded_outputs.get("androguard_components") or {}
        for activity in androguard_components.get("activities") or []:
            if not isinstance(activity, dict):
                continue
            candidates.append(
                self._first_non_empty(
                    activity.get("name"),
                    activity.get("class_name"),
                )
            )

        sensitive: list[str] = []
        for candidate in candidates:
            text = str(candidate or "").strip()
            if not text:
                continue
            normalized = text.replace(".", "/")
            if package_prefix and package_prefix not in normalized:
                continue
            simple_name = normalized.rsplit("/", 1)[-1].split(";")[0]
            if self.SENSITIVE_UI_HINT_PATTERN.search(simple_name) and simple_name not in sensitive:
                sensitive.append(simple_name)
        return sensitive

    def _is_network_api_call(self, item: dict[str, Any]) -> bool:
        categories = {str(category).strip().lower() for category in (item.get("categories") or [])}
        if "network" in categories:
            return True
        signature = self._api_call_signature(item).lower()
        return any(hint in signature for hint in self.NETWORK_API_HINTS)

    def _is_hash_api_call(self, item: dict[str, Any]) -> bool:
        categories = {str(category).strip().lower() for category in (item.get("categories") or [])}
        if "crypto" in categories:
            return True
        signature = self._api_call_signature(item).lower()
        method_name = self._api_call_method_name(item).lower()
        if any(hint in signature for hint in self.HASH_API_HINTS):
            return True
        return method_name in {"digest", "dofinal"}

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
