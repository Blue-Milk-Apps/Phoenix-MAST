"""Build the default iOS permissions section."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from domain.post_scan.utilities import first_non_empty

PERMISSION_DETAILS: dict[str, dict[str, str]] = {
    "NSCameraUsageDescription": {
        "status": "dangerous",
        "info": "Access Camera",
        "general_description": "Permits access to the device's camera hardware.",
    },
    "NSFaceIDUsageDescription": {
        "status": "normal",
        "info": "Use Face ID",
        "general_description": "Permits use of Face ID for biometric authentication.",
    },
    "NSMicrophoneUsageDescription": {
        "status": "dangerous",
        "info": "Access Microphone",
        "general_description": "Permits recording audio with the device microphone.",
    },
    "NSContactsUsageDescription": {
        "status": "dangerous",
        "info": "Access Contacts",
        "general_description": "Permits access to the user's contacts database.",
    },
    "NSCalendarsUsageDescription": {
        "status": "dangerous",
        "info": "Access Calendar",
        "general_description": "Permits access to the user's calendar data.",
    },
    "NSLocationWhenInUseUsageDescription": {
        "status": "dangerous",
        "info": "Access Location While Using App",
        "general_description": "Permits access to the device's location while the app is in use.",
    },
    "NSLocationAlwaysAndWhenInUseUsageDescription": {
        "status": "dangerous",
        "info": "Always Access Location",
        "general_description": "Permits continuous access to the device's location, including in the background.",
    },
    "NSLocationAlwaysUsageDescription": {
        "status": "dangerous",
        "info": "Always Access Location",
        "general_description": "Permits continuous access to the device's location, including in the background.",
    },
    "NSBluetoothAlwaysUsageDescription": {
        "status": "dangerous",
        "info": "Access Bluetooth",
        "general_description": "Permits scanning for and connecting to nearby Bluetooth devices.",
    },
    "NSBluetoothPeripheralUsageDescription": {
        "status": "dangerous",
        "info": "Access Bluetooth",
        "general_description": "Permits use of Bluetooth peripherals and nearby Bluetooth communication.",
    },
    "NSPhotoLibraryUsageDescription": {
        "status": "dangerous",
        "info": "Access Photos",
        "general_description": "Permits reading from the user's photo library.",
    },
    "NSPhotoLibraryAddUsageDescription": {
        "status": "dangerous",
        "info": "Add to Photos",
        "general_description": "Permits writing content to the user's photo library.",
    },
    "NSNearbyInteractionUsageDescription": {
        "status": "normal",
        "info": "Nearby Interaction",
        "general_description": "Permits use of nearby interaction features with supported devices.",
    },
    "NSHealthShareUsageDescription": {
        "status": "dangerous",
        "info": "Read Health Data",
        "general_description": "Permits reading health data from the Health app.",
    },
    "NSHealthUpdateUsageDescription": {
        "status": "dangerous",
        "info": "Write Health Data",
        "general_description": "Permits writing health data to the Health app.",
    },
    "NSAppleMusicUsageDescription": {
        "status": "normal",
        "info": "Access Media Library",
        "general_description": "Permits access to the user's Apple Music and media library information.",
    },
    "NSMotionUsageDescription": {
        "status": "dangerous",
        "info": "Access Motion Data",
        "general_description": "Permits access to motion and fitness activity data.",
    },
    "NSRemindersUsageDescription": {
        "status": "dangerous",
        "info": "Access Reminders",
        "general_description": "Permits access to the user's reminders data.",
    },
    "NSSpeechRecognitionUsageDescription": {
        "status": "dangerous",
        "info": "Speech Recognition",
        "general_description": "Permits use of speech recognition services on user audio.",
    },
    "NFCReaderUsageDescription": {
        "status": "normal",
        "info": "Use NFC",
        "general_description": "Permits reading supported NFC tags with the device.",
    },
    "NSUserTrackingUsageDescription": {
        "status": "dangerous",
        "info": "Track User",
        "general_description": "Permits tracking the user or device across apps and websites.",
    },
}


@dataclass
class IOSPermissions:
    items: list[dict[str, str]]

    def __init__(self, loaded_outputs: dict[str, Any]) -> None:
        self.items = self._build_items(loaded_outputs)

    @classmethod
    def _build_items(cls, loaded_outputs: dict[str, Any]) -> list[dict[str, str]]:
        permissions_by_key: dict[str, dict[str, str]] = {}
        for document in (loaded_outputs.get("plist_outputs") or {}).values():
            if not isinstance(document, dict):
                continue
            privacy = document.get("privacy")
            if not isinstance(privacy, dict):
                continue
            permissions = privacy.get("permissions")
            if not isinstance(permissions, list):
                continue
            for item in permissions:
                if not isinstance(item, dict):
                    continue
                key = str(item.get("key", "")).strip()
                if not key:
                    continue
                purpose = first_non_empty(item.get("purpose"))
                existing = permissions_by_key.get(key)
                if existing is None:
                    permissions_by_key[key] = cls._permission_row(key, purpose)
                    continue
                if not existing["usage_description"] and purpose:
                    existing["usage_description"] = purpose

        return [permissions_by_key[key] for key in sorted(permissions_by_key)]

    @staticmethod
    def _permission_row(key: str, purpose: str) -> dict[str, str]:
        details = PERMISSION_DETAILS.get(key, {})
        return {
            "permission": key,
            "status": details.get("status", "normal"),
            "info": details.get("info", ""),
            "usage_description": purpose,
            "general_description": details.get("general_description", ""),
        }
