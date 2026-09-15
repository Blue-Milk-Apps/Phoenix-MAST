"""Build Android application functionality evidence."""

from dataclasses import dataclass
from typing import Any

from domain.post_scan.utilities import first_non_empty


@dataclass
class FunctionalityBuilder:
    items: dict[str, dict[str, Any]]

    KEYS = (
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
    )
    CHECK_IDS = {
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
    RULE_IDS = {
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
    PERMISSIONS = {
        "Background Execution": {
            "android.permission.FOREGROUND_SERVICE",
            "android.permission.FOREGROUND_SERVICE_CONNECTED_DEVICE",
            "android.permission.RECEIVE_BOOT_COMPLETED",
        },
        "Camera": {"android.permission.CAMERA"},
        "Microphone": {"android.permission.RECORD_AUDIO"},
        "NFC": {"android.permission.NFC"},
        "Fingerprint": {"android.permission.USE_BIOMETRIC", "android.permission.USE_FINGERPRINT"},
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
        "Calendar": {"android.permission.READ_CALENDAR", "android.permission.WRITE_CALENDAR"},
        "Photos": {
            "android.permission.READ_EXTERNAL_STORAGE",
            "android.permission.READ_MEDIA_IMAGES",
            "android.permission.READ_MEDIA_VISUAL_USER_SELECTED",
            "android.permission.WRITE_EXTERNAL_STORAGE",
        },
        "Sensors": {"android.permission.BODY_SENSORS", "android.permission.BODY_SENSORS_BACKGROUND"},
    }

    def __init__(self, loaded_outputs: dict[str, Any]) -> None:
        permissions = {
            first_non_empty(item.get("name"))
            for item in ((loaded_outputs.get("aapt2_permissions") or {}).get("permissions") or [])
        }
        permissions.discard("")
        self.items = {key: {"present": False, "explanation": self._absent_explanation(key)} for key in self.KEYS}
        permission_evidence = {
            key: sorted(names & permissions) for key, names in self.PERMISSIONS.items() if names & permissions
        }
        opengrep_evidence: dict[str, str] = {}
        for result in (loaded_outputs.get("opengrep") or {}).get("results") or []:
            capability = self._capability(result)
            if capability in self.items:
                opengrep_evidence.setdefault(capability, self._result_explanation(result))
        for key in self.KEYS:
            matched, explanation = permission_evidence.get(key, []), opengrep_evidence.get(key, "")
            if matched or explanation:
                self.items[key] = {"present": True, "explanation": self._explanation(key, matched, explanation)}

    @classmethod
    def _capability(cls, result: dict[str, Any]) -> str:
        if (rule_id := str(result.get("check_id", "")).strip()) in cls.RULE_IDS:
            return cls.RULE_IDS[rule_id]
        metadata = ((result.get("extra") or {}).get("metadata") or {}).get("phoenix") or {}
        check_id, title = metadata.get("check_id"), str(metadata.get("title", "")).lower()
        if check_id == 60:
            return "Contacts" if "contact" in title else "Calendar" if "calendar" in title else ""
        if check_id in cls.CHECK_IDS:
            return cls.CHECK_IDS[check_id]
        for token, capability in (
            ("background execution", "Background Execution"),
            ("camera", "Camera"),
            ("microphone", "Microphone"),
            ("nfc", "NFC"),
            ("bluetooth", "Bluetooth"),
            ("contact", "Contacts"),
            ("calendar", "Calendar"),
            ("location", "Location"),
        ):
            if token in title:
                return capability
        return "Google Cloud Messaging" if "push notification" in title or "google cloud messaging" in title else ""

    @staticmethod
    def _result_explanation(result: dict[str, Any]) -> str:
        extra = result.get("extra") or {}
        metadata = (extra.get("metadata") or {}).get("phoenix") or {}
        return (
            str(metadata.get("description", "")).strip()
            or str(metadata.get("title", "")).strip()
            or str(extra.get("message", "")).strip()
        )

    @staticmethod
    def _label(capability: str) -> str:
        return {
            "Audio": "audio",
            "Background Execution": "background execution",
            "Health Data": "health data",
            "Payment Services": "payment services",
            "Secure RNG": "secure RNG",
            "Bluetooth": "Bluetooth",
            "SMS": "SMS",
            "NFC": "NFC",
            "Camera Delegation": "camera delegation",
            "Device Administrator": "device administrator",
            "In-App Purchases": "in-app purchases",
            "Google Cloud Messaging": "Google Cloud Messaging",
            "USB Devices": "USB device",
            "Photos": "photo",
            "Sensors": "sensor",
        }.get(capability, capability.lower())

    @classmethod
    def _absent_explanation(cls, capability: str) -> str:
        return f"No permission or scan evidence indicated {cls._label(capability)} functionality."

    @classmethod
    def _explanation(cls, capability: str, permissions: list[str], opengrep: str) -> str:
        permission_text = ""
        if permissions:
            noun = "permission" if len(permissions) == 1 else "permissions"
            permission_text = (
                f"{noun} {', '.join(permissions)}, which may indicate {cls._label(capability)} functionality."
            )
        return (
            f"{opengrep} The app also declares {permission_text}"
            if opengrep and permission_text
            else opengrep or permission_text
        )
