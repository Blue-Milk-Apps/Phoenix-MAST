"""Build Android permission details for post-scan reports."""

from dataclasses import dataclass
from typing import Any

from domain.post_scan.utilities import first_non_empty


@dataclass
class PermissionsBuilder:
    items: list[dict[str, str]]

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

    def __init__(self, loaded_outputs: dict[str, Any]) -> None:
        aapt2_permissions = loaded_outputs.get("aapt2_permissions") or {}
        declared_permissions = self._declared_permission_map(loaded_outputs.get("apktool_permissions") or {})
        self.items = []

        for permission in aapt2_permissions.get("permissions") or []:
            name = first_non_empty(permission.get("name"))
            if not name:
                continue
            protection_level = first_non_empty(permission.get("protection_level_hint"))
            self.items.append(
                {
                    "permission": name,
                    "status": self._normalize_status(protection_level),
                    "info": self._permission_info(protection_level),
                    "usage_description": "",
                    "general_description": self._description(name, declared_permissions),
                }
            )

    @staticmethod
    def _declared_permission_map(apktool_permissions: dict[str, Any]) -> dict[str, str]:
        descriptions: dict[str, str] = {}
        for permission in apktool_permissions.get("declared") or []:
            name = str(permission.get("value", "")).strip()
            if not name:
                continue
            level = str((permission.get("context") or {}).get("protection_level", "")).strip()
            descriptions[name] = f"Declared permission ({level})" if level else "Declared permission"
        return descriptions

    @classmethod
    def _description(cls, name: str, declared_permissions: dict[str, str]) -> str:
        if name in cls.ANDROID_PERMISSION_DESCRIPTIONS:
            return cls.ANDROID_PERMISSION_DESCRIPTIONS[name]
        if name in declared_permissions:
            return declared_permissions[name]
        suffix = name.rsplit(".", 1)[-1].replace("_", " ").lower()
        return suffix[:1].upper() + suffix[1:] + "." if suffix else ""

    @staticmethod
    def _normalize_status(protection_level: str) -> str:
        return "dangerous" if protection_level.strip().lower() == "dangerous" else "normal"

    @staticmethod
    def _permission_info(protection_level: str) -> str:
        normalized = protection_level.strip().lower()
        if normalized in {"dangerous", "signature"}:
            return normalized
        return normalized.replace("_", " ")
