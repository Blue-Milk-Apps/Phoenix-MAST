"""Build iOS functionality section from loaded scan outputs."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any


@dataclass
class FunctionalityEntry:
    present: bool = False
    explanation: str = ""


@dataclass
class IOSFunctionality:
    Camera: FunctionalityEntry = field(default_factory=FunctionalityEntry)
    Biometric_Authentication: FunctionalityEntry = field(default_factory=FunctionalityEntry)
    Networking: FunctionalityEntry = field(default_factory=FunctionalityEntry)
    Secure_RNG: FunctionalityEntry = field(default_factory=FunctionalityEntry)
    Push_Notifications: FunctionalityEntry = field(default_factory=FunctionalityEntry)
    Audio: FunctionalityEntry = field(default_factory=FunctionalityEntry)
    Contacts: FunctionalityEntry = field(default_factory=FunctionalityEntry)
    Geofencing: FunctionalityEntry = field(default_factory=FunctionalityEntry)
    Health_Data: FunctionalityEntry = field(default_factory=FunctionalityEntry)
    Location: FunctionalityEntry = field(default_factory=FunctionalityEntry)
    Maps: FunctionalityEntry = field(default_factory=FunctionalityEntry)
    Payment_Services: FunctionalityEntry = field(default_factory=FunctionalityEntry)
    SMS: FunctionalityEntry = field(default_factory=FunctionalityEntry)
    Bluetooth: FunctionalityEntry = field(default_factory=FunctionalityEntry)
    Camera_Delegation: FunctionalityEntry = field(default_factory=FunctionalityEntry)
    Calendar: FunctionalityEntry = field(default_factory=FunctionalityEntry)
    In_App_Purchases: FunctionalityEntry = field(default_factory=FunctionalityEntry)
    Keychain: FunctionalityEntry = field(default_factory=FunctionalityEntry)
    Microphone: FunctionalityEntry = field(default_factory=FunctionalityEntry)
    NFC: FunctionalityEntry = field(default_factory=FunctionalityEntry)
    Photos: FunctionalityEntry = field(default_factory=FunctionalityEntry)
    Sensors: FunctionalityEntry = field(default_factory=FunctionalityEntry)
    Telephony: FunctionalityEntry = field(default_factory=FunctionalityEntry)
    USB_Devices: FunctionalityEntry = field(default_factory=FunctionalityEntry)
    Nearby_Interaction: FunctionalityEntry = field(default_factory=FunctionalityEntry)

    def __init__(self, loaded_outputs: dict[str, Any]) -> None:
        permission_keys = self._plist_permission_keys(loaded_outputs)
        entitlements = self._plist_entitlements(loaded_outputs)
        background_modes = self._plist_background_modes(loaded_outputs)
        url_schemes = self._plist_url_schemes(loaded_outputs)
        required_capabilities = self._plist_required_device_capabilities(loaded_outputs)
        opengrep_hits = self._opengrep_descriptions_by_capability(loaded_outputs)
        strings_outputs = loaded_outputs.get("strings_outputs") or {}

        self.Camera = self._entry_from_sources(
            plist_keys={"NSCameraUsageDescription"},
            permission_keys=permission_keys,
        )
        self.Biometric_Authentication = self._entry_from_sources(
            plist_keys={"NSFaceIDUsageDescription"},
            permission_keys=permission_keys,
            opengrep_hits=opengrep_hits.get("Biometric Authentication", []),
        )
        self.Networking = self._networking_entry(
            loaded_outputs,
            url_schemes,
            opengrep_hits.get("Networking", []),
            strings_outputs,
        )
        self.Secure_RNG = self._entry_from_sources(
            opengrep_hits=opengrep_hits.get("Secure RNG", []),
        )
        self.Push_Notifications = self._entry_from_sources(
            entitlements=entitlements,
            entitlement_keys={"aps_environment"},
            background_modes=background_modes,
            background_mode_values={"remote-notification"},
            opengrep_hits=opengrep_hits.get("Push Notifications", []),
        )
        self.Audio = self._entry_from_sources()
        self.Contacts = self._entry_from_sources(
            plist_keys={"NSContactsUsageDescription"},
            permission_keys=permission_keys,
        )
        self.Geofencing = self._entry_from_sources()
        self.Health_Data = self._entry_from_sources(
            plist_keys={"NSHealthShareUsageDescription", "NSHealthUpdateUsageDescription"},
            permission_keys=permission_keys,
            entitlements=entitlements,
            entitlement_keys={"healthkit"},
        )
        self.Location = self._entry_from_sources(
            plist_keys={
                "NSLocationWhenInUseUsageDescription",
                "NSLocationAlwaysAndWhenInUseUsageDescription",
                "NSLocationAlwaysUsageDescription",
            },
            permission_keys=permission_keys,
        )
        self.Maps = self._maps_entry(url_schemes)
        self.Payment_Services = self._entry_from_sources(
            entitlements=entitlements,
            entitlement_keys={"merchant_ids", "in_app_payments"},
        )
        self.SMS = self._entry_from_sources()
        self.Bluetooth = self._entry_from_sources(
            plist_keys={"NSBluetoothAlwaysUsageDescription", "NSBluetoothPeripheralUsageDescription"},
            permission_keys=permission_keys,
        )
        self.Camera_Delegation = self._entry_from_sources()
        self.Calendar = self._entry_from_sources(
            plist_keys={"NSCalendarsUsageDescription"},
            permission_keys=permission_keys,
        )
        self.In_App_Purchases = self._entry_from_sources()
        self.Keychain = self._entry_from_sources(
            entitlements=entitlements,
            entitlement_keys={"keychain_access_groups"},
        )
        self.Microphone = self._entry_from_sources(
            plist_keys={"NSMicrophoneUsageDescription"},
            permission_keys=permission_keys,
        )
        self.NFC = self._nfc_entry(permission_keys, required_capabilities)
        self.Photos = self._entry_from_sources(
            plist_keys={"NSPhotoLibraryUsageDescription", "NSPhotoLibraryAddUsageDescription"},
            permission_keys=permission_keys,
        )
        self.Sensors = self._entry_from_sources()
        self.Telephony = self._telephony_entry(
            url_schemes,
            opengrep_hits.get("Telephony", []),
            strings_outputs,
        )
        self.USB_Devices = self._usb_devices_entry(
            loaded_outputs,
            opengrep_hits.get("USB Devices", []),
            strings_outputs,
        )
        self.Nearby_Interaction = self._entry_from_sources(
            plist_keys={"NSNearbyInteractionUsageDescription"},
            permission_keys=permission_keys,
        )

    def _entry_from_sources(
        self,
        *,
        plist_keys: set[str] | None = None,
        permission_keys: set[str] | None = None,
        entitlements: dict[str, Any] | None = None,
        entitlement_keys: set[str] | None = None,
        background_modes: set[str] | None = None,
        background_mode_values: set[str] | None = None,
        opengrep_hits: list[str] | None = None,
    ) -> FunctionalityEntry:
        explanation_parts: list[str] = []

        for key in sorted((plist_keys or set()) & (permission_keys or set())):
            explanation_parts.append(f"plist key {key} present.")

        if entitlements and entitlement_keys:
            for key in sorted(entitlement_keys):
                value = entitlements.get(key)
                if self._has_entitlement_value(value):
                    explanation_parts.append(f"entitlement {key} present.")

        if background_modes and background_mode_values:
            for mode in sorted(background_mode_values & background_modes):
                explanation_parts.append(f"background mode {mode} declared.")

        for description in opengrep_hits or []:
            if description and description not in explanation_parts:
                explanation_parts.append(description)

        return self._entry(bool(explanation_parts), explanation_parts)

    def _networking_entry(
        self,
        loaded_outputs: dict[str, Any],
        url_schemes: dict[str, set[str]],
        opengrep_hits: list[str],
        strings_outputs: dict[str, str],
    ) -> FunctionalityEntry:
        explanation_parts: list[str] = []
        if self._has_ats_configuration(loaded_outputs):
            explanation_parts.append("Info.plist declares NSAppTransportSecurity.")
        if url_schemes.get("declared_schemes") or url_schemes.get("queried_schemes"):
            explanation_parts.append("Info.plist declares URL scheme handling.")
        for description in opengrep_hits:
            if description and description not in explanation_parts:
                explanation_parts.append(description)
        if not explanation_parts and self._strings_indicate_networking(strings_outputs):
            explanation_parts.append("strings output contains URL or HTTP indicators.")
        return self._entry(bool(explanation_parts), explanation_parts)

    def _maps_entry(self, url_schemes: dict[str, set[str]]) -> FunctionalityEntry:
        matched = sorted(
            scheme
            for scheme in url_schemes.get("queried_schemes", set())
            if str(scheme).lower() in {"maps", "map", "comgooglemaps", "waze"}
        )
        if not matched:
            return self._entry(False, [])
        return self._entry(True, [f"queried URL schemes {', '.join(matched)} declared."])

    def _nfc_entry(self, permission_keys: set[str], required_capabilities: set[str]) -> FunctionalityEntry:
        if "NFCReaderUsageDescription" in permission_keys:
            return self._entry(True, ["plist key NFCReaderUsageDescription present."])
        matched_caps = sorted(cap for cap in required_capabilities if "nfc" in cap.lower())
        if matched_caps:
            return self._entry(True, [f"required device capabilities include {', '.join(matched_caps)}."])
        return self._entry(False, [])

    def _telephony_entry(
        self,
        url_schemes: dict[str, set[str]],
        opengrep_hits: list[str],
        strings_outputs: dict[str, str],
    ) -> FunctionalityEntry:
        explanation_parts: list[str] = []
        matched = sorted(
            scheme
            for scheme in url_schemes.get("queried_schemes", set()) | url_schemes.get("declared_schemes", set())
            if str(scheme).lower() in {"tel", "telprompt", "sms"}
        )
        if matched:
            explanation_parts.append(f"URL schemes {', '.join(matched)} declared or queried.")
        for description in opengrep_hits:
            if description and description not in explanation_parts:
                explanation_parts.append(description)
        if not explanation_parts and self._strings_indicate_telephony(strings_outputs):
            explanation_parts.append("strings output references telephony APIs or URL schemes.")
        return self._entry(bool(explanation_parts), explanation_parts)

    def _usb_devices_entry(
        self,
        loaded_outputs: dict[str, Any],
        opengrep_hits: list[str],
        strings_outputs: dict[str, str],
    ) -> FunctionalityEntry:
        explanation_parts: list[str] = []
        protocols = self._external_accessory_protocols(loaded_outputs)
        if protocols:
            explanation_parts.append(f"external accessory protocols declared: {', '.join(protocols)}.")
        for description in opengrep_hits:
            if description and description not in explanation_parts:
                explanation_parts.append(description)
        if not explanation_parts and self._strings_indicate_usb(strings_outputs):
            explanation_parts.append("strings output references external accessory APIs.")
        return self._entry(bool(explanation_parts), explanation_parts)

    @staticmethod
    def _entry(present: bool, explanation_parts: list[str]) -> FunctionalityEntry:
        explanation = " ".join(part.strip() for part in explanation_parts if part.strip()) if present else ""
        return FunctionalityEntry(present=present, explanation=explanation)

    @staticmethod
    def _plist_documents(loaded_outputs: dict[str, Any]) -> list[dict[str, Any]]:
        return [
            document for document in (loaded_outputs.get("plist_outputs") or {}).values() if isinstance(document, dict)
        ]

    def _plist_permission_keys(self, loaded_outputs: dict[str, Any]) -> set[str]:
        keys: set[str] = set()
        for document in self._plist_documents(loaded_outputs):
            for item in (document.get("privacy") or {}).get("permissions") or []:
                if isinstance(item, dict):
                    key = str(item.get("key", "")).strip()
                    if key:
                        keys.add(key)
        return keys

    def _plist_background_modes(self, loaded_outputs: dict[str, Any]) -> set[str]:
        values: set[str] = set()
        for document in self._plist_documents(loaded_outputs):
            for item in document.get("background_modes") or []:
                text = str(item).strip()
                if text:
                    values.add(text)
        return values

    def _plist_entitlements(self, loaded_outputs: dict[str, Any]) -> dict[str, Any]:
        merged: dict[str, Any] = {}
        for document in self._plist_documents(loaded_outputs):
            entitlements = document.get("entitlements") or {}
            if isinstance(entitlements, dict):
                for key, value in entitlements.items():
                    if key not in merged or self._has_entitlement_value(value):
                        merged[key] = value
        for document in (loaded_outputs.get("ipsw_outputs") or {}).values():
            if not isinstance(document, dict):
                continue
            values = ((document.get("analysis") or {}).get("entitlements") or {}).get("values") or {}
            if not isinstance(values, dict):
                continue
            if "aps-environment" in values:
                merged["aps_environment"] = values.get("aps-environment")
            if "keychain-access-groups" in values:
                merged["keychain_access_groups"] = values.get("keychain-access-groups")
            if "com.apple.developer.in-app-payments" in values:
                merged["in_app_payments"] = values.get("com.apple.developer.in-app-payments")
            if "com.apple.developer.healthkit" in values:
                merged["healthkit"] = values.get("com.apple.developer.healthkit")
        return merged

    def _plist_url_schemes(self, loaded_outputs: dict[str, Any]) -> dict[str, set[str]]:
        declared: set[str] = set()
        queried: set[str] = set()
        for document in self._plist_documents(loaded_outputs):
            schemes = document.get("url_schemes") or {}
            if not isinstance(schemes, dict):
                continue
            for item in schemes.get("declared_schemes") or []:
                text = str(item).strip()
                if text:
                    declared.add(text)
            for item in schemes.get("queried_schemes") or []:
                text = str(item).strip()
                if text:
                    queried.add(text)
        return {"declared_schemes": declared, "queried_schemes": queried}

    def _plist_required_device_capabilities(self, loaded_outputs: dict[str, Any]) -> set[str]:
        caps: set[str] = set()
        for document in self._plist_documents(loaded_outputs):
            for item in (document.get("app_meta") or {}).get("required_device_capabilities") or []:
                text = str(item).strip()
                if text:
                    caps.add(text)
        return caps

    def _external_accessory_protocols(self, loaded_outputs: dict[str, Any]) -> list[str]:
        protocols: list[str] = []
        for document in self._plist_documents(loaded_outputs):
            plist = document.get("plist") or {}
            if not isinstance(plist, dict):
                continue
            for item in plist.get("UISupportedExternalAccessoryProtocols", []) or []:
                text = str(item).strip()
                if text:
                    protocols.append(text)
        return list(dict.fromkeys(protocols))

    @staticmethod
    def _opengrep_descriptions_by_capability(loaded_outputs: dict[str, Any]) -> dict[str, list[str]]:
        mapping: dict[str, list[str]] = {
            "Biometric Authentication": [],
            "Networking": [],
            "Secure RNG": [],
            "Push Notifications": [],
            "Telephony": [],
            "USB Devices": [],
        }
        for result in (loaded_outputs.get("opengrep") or {}).get("results") or []:
            extra = result.get("extra") if isinstance(result, dict) else {}
            phoenix = ((extra or {}).get("metadata") or {}).get("phoenix") or {}
            candidates = [
                str(result.get("check_id", "")).strip(),
                str(phoenix.get("title", "")).strip(),
                str(phoenix.get("description", "")).strip(),
            ]
            haystack = " ".join(text.lower() for text in candidates if text)
            description = str(phoenix.get("description", "")).strip() or str(phoenix.get("title", "")).strip()
            if not description:
                continue
            if any(token in haystack for token in ("secure rng", "secrandom", "random number")):
                mapping["Secure RNG"].append(description)
            if any(token in haystack for token in ("biometric", "face id", "touch id")):
                mapping["Biometric Authentication"].append(description)
            if any(token in haystack for token in ("push notification", "apns", "remote notification")):
                mapping["Push Notifications"].append(description)
            if any(token in haystack for token in ("network", "urlsession", "cfnetwork", "http", "https")):
                mapping["Networking"].append(description)
            if any(token in haystack for token in ("telephony", "coretelephony", "tel:", "sms:")):
                mapping["Telephony"].append(description)
            if any(token in haystack for token in ("usb", "external accessory", "eaaccessory", "accessory protocol")):
                mapping["USB Devices"].append(description)
        return {key: list(dict.fromkeys(values)) for key, values in mapping.items()}

    @staticmethod
    def _has_ats_configuration(loaded_outputs: dict[str, Any]) -> bool:
        for document in (loaded_outputs.get("plist_outputs") or {}).values():
            if not isinstance(document, dict):
                continue
            ats = document.get("ats")
            if isinstance(ats, dict) and ats:
                return True
        return False

    @staticmethod
    def _strings_indicate_networking(strings_outputs: dict[str, str]) -> bool:
        pattern = re.compile(r"https?://", re.IGNORECASE)
        return any(pattern.search(content or "") for content in strings_outputs.values())

    @staticmethod
    def _strings_indicate_telephony(strings_outputs: dict[str, str]) -> bool:
        pattern = re.compile(r"(coretelephony|cttelephony|tel:|sms:)", re.IGNORECASE)
        return any(pattern.search(content or "") for content in strings_outputs.values())

    @staticmethod
    def _strings_indicate_usb(strings_outputs: dict[str, str]) -> bool:
        pattern = re.compile(r"(externalaccessory|eaaccessory|uisupportedexternalaccessoryprotocols)", re.IGNORECASE)
        return any(pattern.search(content or "") for content in strings_outputs.values())

    @staticmethod
    def _has_entitlement_value(value: object) -> bool:
        if isinstance(value, list):
            return any(str(item).strip() for item in value)
        if isinstance(value, bool):
            return value
        return bool(str(value or "").strip())
