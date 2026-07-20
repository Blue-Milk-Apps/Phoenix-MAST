"""Android binary detail extractor for post-scan processing."""

from __future__ import annotations

import re
from dataclasses import asdict
from typing import Any

from domain.post_scan.android.app_certificate_builder import AppCertificateBuilder
from domain.post_scan.android.app_component_builder import AppComponentBuilder
from domain.post_scan.android.app_info_builder import AndroidAppInfoBuilder
from domain.post_scan.android.application_builder import ApplicationBuilder
from domain.post_scan.android.code_evidence_builder import CodeEvidenceBuilder
from domain.post_scan.android.deep_links_builder import DeepLinksBuilder
from domain.post_scan.android.endpoints_builder import EndpointsBuilder
from domain.post_scan.android.file_info_builder import FileInfoBuilder
from domain.post_scan.android.functionality_builder import FunctionalityBuilder
from domain.post_scan.android.hardcoded_values_builder import HardcodedValuesBuilder
from domain.post_scan.android.permissions_builder import PermissionsBuilder
from domain.post_scan.android.resilience_evidence_builder import ResilienceEvidenceBuilder
from ports.scan_detail_extractor_port import ScanDetailExtractorPort


class AndroidBinaryScanDetailExtractor(ScanDetailExtractorPort):
    """Extract Android-binary-specific sections from loaded scan outputs."""

    ENCODED_SECRET_PATTERN = re.compile(r"(?<![A-Za-z0-9+/=])[A-Za-z0-9+/]{40,}={0,2}(?![A-Za-z0-9+/=])")
    JVM_DESCRIPTOR_PATTERN = re.compile(r"^\+?L(?:[A-Za-z0-9_$]+/)+[A-Za-z0-9_$]+$")
    SECRET_LABEL_PATTERN = re.compile(
        r"(?i)^(?:api[_-]?key|client[_-]?secret|secret[_-]?key|access[_-]?token|secretkey)$"
    )
    STORAGE_CREDENTIAL_HINT_PATTERN = re.compile(
        r"(?i)(?:auth|credential|login|passw(?:or)?d|token|session|rememberme)"
    )
    PASSWORD_HINT_PATTERN = re.compile(r"(?i)(?:passw(?:or)?d|passwd|pwd|newpassword|passcode|credential|login|auth)")
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
        app_info = AndroidAppInfoBuilder(loaded_outputs)
        application = ApplicationBuilder(loaded_outputs)
        app_components = AppComponentBuilder(loaded_outputs)
        certificate = AppCertificateBuilder(loaded_outputs)
        code_evidence = CodeEvidenceBuilder(loaded_outputs, app_components, application, app_info)
        file_info = FileInfoBuilder(loaded_outputs)
        permissions = PermissionsBuilder(loaded_outputs).items
        functionality = FunctionalityBuilder(loaded_outputs).items
        deeplink_builder = DeepLinksBuilder(loaded_outputs)
        hardcoded_values = HardcodedValuesBuilder(loaded_outputs)
        endpoints = EndpointsBuilder(loaded_outputs).items

        return {
            "app_info": asdict(app_info),
            "application": asdict(application),
            "app_components": asdict(app_components),
            "certificate": asdict(certificate),
            "code_evidence": asdict(code_evidence),
            "file_info": asdict(file_info),
            "permissions": permissions,
            "functionality": functionality,
            "network_evidence": self._build_network_evidence(loaded_outputs, hardcoded_values),
            "resilience_evidence": asdict(ResilienceEvidenceBuilder(loaded_outputs)),
            "storage_evidence": self._build_storage_evidence(loaded_outputs, hardcoded_values),
            "deep_links": asdict(deeplink_builder),
            "hardcoded_values": asdict(hardcoded_values),
            "endpoints": endpoints,
        }

    def _build_network_evidence(
        self, loaded_outputs: dict[str, Any], hardcoded_values: HardcodedValuesBuilder
    ) -> dict[str, Any]:
        network_security = loaded_outputs.get("apktool_network_security_config") or {}
        aapt2_application = loaded_outputs.get("aapt2_application") or {}
        aapt2_posture = loaded_outputs.get("aapt2_manifest_security_posture") or {}
        androguard_api_calls = loaded_outputs.get("androguard_api_calls") or {}
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
            lambda item: (
                self._caller_matches_package(item, package_prefix)
                and (
                    "allow_all_hostname_verifier" in self._api_call_signature(item).lower()
                    or "sethostnameverifier" in self._api_call_signature(item).lower()
                )
            ),
        )
        trust_manager_hits = self._matching_api_call_sites(
            api_call_items,
            lambda item: (
                self._caller_matches_package(item, package_prefix)
                and "checkservertrusted" in self._api_call_caller_signature(item).lower()
            ),
        )
        listening_port_hits = self._matching_api_call_sites(
            api_call_items,
            lambda item: (
                self._caller_matches_package(item, package_prefix)
                and any(
                    token in self._api_call_signature(item).lower()
                    for token in ("serversocket", "localserversocket", "datagramsocket; bind")
                )
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
            "manifest_cleartext_traffic_permitted": self._coerce_true(aapt2_posture.get("cleartext_traffic_permitted"))
            if aapt2_posture
            else self._coerce_bool_like(aapt2_application.get("uses_cleartext_traffic")),
        }

    def _build_storage_evidence(
        self, loaded_outputs: dict[str, Any], hardcoded_values: HardcodedValuesBuilder
    ) -> dict[str, Any]:
        aapt2_permissions = loaded_outputs.get("aapt2_permissions") or {}
        androguard_api_calls = loaded_outputs.get("androguard_api_calls") or {}

        declared_permissions = {
            self._first_non_empty(permission.get("name")) for permission in aapt2_permissions.get("permissions") or []
        }
        declared_permissions.discard("")

        external_storage_permissions = sorted(
            permission for permission in declared_permissions if permission in self.EXTERNAL_STORAGE_PERMISSIONS
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
            caller for caller in shared_preferences_callers if self.STORAGE_CREDENTIAL_HINT_PATTERN.search(caller)
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
            hardcoded_values=hardcoded_values,
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
                if (
                    location not in sample_locations_by_category[category]
                    and len(sample_locations_by_category[category]) < 5
                ):
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
                    if (
                        value not in sample_values_by_category[category]
                        and len(sample_values_by_category[category]) < 5
                    ):
                        sample_values_by_category[category].append(value)

                for xref in xrefs:
                    if not isinstance(xref, dict):
                        continue
                    signature = self._first_non_empty(xref.get("signature"))
                    if not signature:
                        continue
                    sample_xrefs_by_category.setdefault(category, [])
                    if (
                        signature not in sample_xrefs_by_category[category]
                        and len(sample_xrefs_by_category[category]) < 5
                    ):
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

        metadata = ((result.get("extra") or {}).get("metadata") or {}).get("phoenix") or {}

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
        metadata = (extra.get("metadata") or {}).get("phoenix") or {}
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
        functionality = FunctionalityBuilder(loaded_outputs).items
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

    def _detect_screen_capture_protection(self, loaded_outputs: dict[str, Any]) -> dict[str, Any]:
        package_prefix = self._first_non_empty(
            ((loaded_outputs.get("aapt2_identity") or {}).get("package_name")),
            ((loaded_outputs.get("androguard_metadata") or {}).get("package")),
        ).replace(".", "/")
        api_calls = list(((loaded_outputs.get("androguard_api_calls") or {}).get("items") or []))
        strings_outputs = loaded_outputs.get("strings_outputs") or {}

        secure_flag_callers = self._matching_api_call_sites(
            api_calls,
            lambda item: self._caller_matches_package(item, package_prefix) and self._is_window_flag_api_call(item),
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
                lambda item: (
                    self._caller_matches_package(item, package_prefix)
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
                    )
                ),
            )
        )
        network_callers = set(
            self._matching_api_call_sites(
                api_calls,
                lambda item: self._caller_matches_package(item, package_prefix) and self._is_network_api_call(item),
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

    def _detect_world_readable_internal_storage(self, api_calls: list[dict[str, Any]]) -> dict[str, Any]:
        world_mode_hits = self._matching_api_call_sites(
            api_calls,
            lambda item: (
                self.WORLD_MODE_PATTERN.search(self._api_call_signature(item)) is not None
                or self.WORLD_MODE_PATTERN.search(self._api_call_caller_signature(item)) is not None
            ),
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
        hardcoded_values: HardcodedValuesBuilder,
    ) -> dict[str, Any]:
        sensitive_callers = [
            caller
            for caller in external_storage_callers
            if self.PASSWORD_HINT_PATTERN.search(caller) or self.SENSITIVE_UI_HINT_PATTERN.search(caller)
        ]
        if sensitive_callers:
            return {"present": True, "evidence": sensitive_callers[0], "details": sensitive_callers[:10]}
        secrets = hardcoded_values.secrets
        external_secret_hits = [secret for secret in secrets if "external" in str(secret.get("location", "")).lower()]
        if external_secret_hits:
            evidence = self._first_non_empty(
                external_secret_hits[0].get("location"),
                external_secret_hits[0].get("value"),
            )
            return {"present": True, "evidence": evidence, "details": external_secret_hits[:10]}
        if not external_storage_callers:
            return {"present": False, "evidence": "no_external_storage_sensitive_hits"}
        return {"present": None, "evidence": ""}

    def _detect_weak_blowfish_key_length(
        self,
        loaded_outputs: dict[str, Any],
        package_prefix: str,
        api_calls: list[dict[str, Any]],
        code_indicator_items: list[dict[str, Any]],
    ) -> dict[str, Any]:
        crypto_callers = self._matching_api_call_sites(
            api_calls,
            lambda item: (
                self._caller_matches_package(item, package_prefix)
                and any(
                    token in self._api_call_signature(item).lower()
                    for token in ("cipher;", "secretkeyspec", "keygenerator", "secretkeyfactory")
                )
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
            value_predicate=lambda value: (
                self.BLOWFISH_PATTERN.search(value) is not None
                and self.WEAK_BLOWFISH_KEY_BITS_PATTERN.search(value) is not None
            ),
        )
        overlapping = [
            caller for caller in crypto_callers if caller in set(blowfish_xrefs) and caller in set(weak_size_xrefs)
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
            lambda item: (
                self._caller_matches_package(item, package_prefix)
                and any(
                    token in self._api_call_signature(item).lower()
                    for token in ("keypairgenerator", "rsakeygenparameterspec", "keyfactory", "rsapublickeyspec")
                )
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
            value_predicate=lambda value: (
                self.RSA_PATTERN.search(value) is not None and self.WEAK_RSA_KEY_BITS_PATTERN.search(value) is not None
            ),
        )
        overlapping = [caller for caller in rsa_callers if caller in set(rsa_xrefs) and caller in set(weak_size_xrefs)]
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
            lambda item: (
                self._caller_matches_package(item, package_prefix)
                and self.XML_PARSER_PATTERN.search(self._api_call_signature(item)) is not None
            ),
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
            lambda item: (
                self._caller_matches_package(item, package_prefix)
                and "android/util/log" in self._api_call_signature(item).lower()
            ),
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
            lambda item: (
                self._caller_matches_package(item, package_prefix)
                and self.SPOOFABLE_IDENTIFIER_PATTERN.search(self._api_call_signature(item)) is not None
            ),
        )
        auth_xrefs = self._matching_string_xrefs(
            loaded_outputs=loaded_outputs,
            value_predicate=lambda value: self.AUTH_VALUE_PATTERN.search(value) is not None,
            xref_predicate=lambda signature: package_prefix in signature.replace(".", "/") if package_prefix else False,
        )
        network_callers = self._matching_api_call_sites(
            api_calls,
            lambda item: self._caller_matches_package(item, package_prefix) and self._is_network_api_call(item),
        )

        overlapping = [
            caller for caller in identifier_callers if caller in set(auth_xrefs) or caller in set(network_callers)
        ]
        if overlapping:
            return {"present": True, "evidence": overlapping[0], "details": overlapping[:10]}
        if identifier_callers:
            return {
                "present": False,
                "evidence": "no_spoofable_authentication_hits",
                "details": identifier_callers[:10],
            }
        return {"present": False, "evidence": "no_spoofable_authentication_hits"}

    def _api_call_method_name(self, item: dict[str, Any]) -> str:
        callee = item.get("callee") or {}
        return self._first_non_empty(callee.get("method_name"))

    def _matching_api_call_sites(
        self,
        api_calls: list[dict[str, Any]],
        predicate: Any,
    ) -> list[str]:
        callers: list[str] = []
        for item in api_calls:
            if not isinstance(item, dict) or not predicate(item):
                continue
            signature = self._first_non_empty(((item.get("caller") or {}).get("signature")))
            if signature:
                callers.append(signature)
        return self._dedupe_preserve_order(callers)

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
