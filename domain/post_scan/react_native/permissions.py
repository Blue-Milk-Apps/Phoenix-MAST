"""Correlate React Native permission declarations with runtime requests."""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from domain.post_scan.react_native.rule_registry import PERMISSION_INVENTORY_RULE_ID_TO_KEY
from domain.post_scan.react_native.scan_extraction_context import ReactNativeScanExtractionContext


@dataclass
class ReactNativePermissions:
    items: list[dict[str, Any]]
    assessed: bool

    DISCLAIMER = (
        "This React Native source assessment cannot determine the final permissions in the packaged "
        "application. The permissions shown are derived from available source, Expo configuration, and native "
        "project metadata; config plugins, native dependencies, build variants, and manifest merging can change "
        "the final Android or iOS permission set."
    )
    ANDROID_CONSTANT_PATTERN = re.compile(
        r"(?:PermissionsAndroid\.PERMISSIONS\.([A-Z0-9_]+)|android\.permission\.([A-Z0-9_]+))"
    )
    CROSS_PLATFORM_PATTERN = re.compile(r"PERMISSIONS\.(ANDROID|IOS)\.([A-Z0-9_]+)")
    EXPO_REQUEST_PATTERN = re.compile(
        r"(Camera|Location|Contacts|Calendar|MediaLibrary|ImagePicker|Notifications|Audio)\."
        r"request[A-Za-z]*PermissionsAsync"
    )
    IOS_PERMISSION_KEYS = {
        "BLUETOOTH": "NSBluetoothAlwaysUsageDescription",
        "CALENDARS": "NSCalendarsUsageDescription",
        "CAMERA": "NSCameraUsageDescription",
        "CONTACTS": "NSContactsUsageDescription",
        "LOCATION_ALWAYS": "NSLocationAlwaysAndWhenInUseUsageDescription",
        "LOCATION_WHEN_IN_USE": "NSLocationWhenInUseUsageDescription",
        "MICROPHONE": "NSMicrophoneUsageDescription",
        "PHOTO_LIBRARY": "NSPhotoLibraryUsageDescription",
        "PHOTO_LIBRARY_ADD_ONLY": "NSPhotoLibraryAddUsageDescription",
        "REMINDERS": "NSRemindersUsageDescription",
        "SPEECH_RECOGNITION": "NSSpeechRecognitionUsageDescription",
    }
    EXPO_MODULE_PERMISSIONS = {
        "Audio": ("Microphone",),
        "Calendar": ("Calendar",),
        "Camera": ("Camera",),
        "Contacts": ("Contacts",),
        "ImagePicker": ("Camera", "Photos"),
        "Location": ("Location",),
        "MediaLibrary": ("Photos",),
        "Notifications": ("Notifications",),
    }
    EXPO_PLUGIN_PERMISSIONS = {
        "expo-audio": ("Microphone",),
        "expo-av": ("Microphone",),
        "expo-calendar": ("Calendar",),
        "expo-camera": ("Camera", "Microphone"),
        "expo-contacts": ("Contacts",),
        "expo-image-picker": ("Camera", "Photos"),
        "expo-location": ("Location",),
        "expo-media-library": ("Photos",),
        "expo-notifications": ("Notifications",),
    }

    def __init__(self, context: ReactNativeScanExtractionContext) -> None:
        records: dict[tuple[str, str], dict[str, Any]] = {}
        self._add_native_declarations(context, records)
        blocked = self._add_expo_declarations(context, records)
        self._add_runtime_requests(context, records, blocked)
        self.items = [
            self._finalize(platform, permission, record) for (platform, permission), record in records.items()
        ]
        self.items.sort(key=lambda item: (item["platform"], item["permission"]))
        self.assessed = bool(
            isinstance(context.android_metadata.get("permissions"), list)
            or isinstance(context.ios_metadata.get("permissions"), list)
            or context.mapping(context.source_metadata.get("expo")).get("assessed") is True
            or context.opengrep_scope_assessed("react_native", frozenset(PERMISSION_INVENTORY_RULE_ID_TO_KEY))
        )

    @classmethod
    def _add_native_declarations(
        cls,
        context: ReactNativeScanExtractionContext,
        records: dict[tuple[str, str], dict[str, Any]],
    ) -> None:
        for item in context.mapping_list(context.android_metadata.get("permissions")):
            permission = context.first_non_empty(item.get("name"))
            if permission:
                cls._record(records, "Android", permission)["declarations"].append("Android manifest")
        for item in context.mapping_list(context.ios_metadata.get("permissions")):
            permission = context.first_non_empty(item.get("key"))
            if not permission:
                continue
            record = cls._record(records, "iOS", permission)
            record["declarations"].append("iOS Info.plist")
            purpose = context.first_non_empty(item.get("purpose"))
            if purpose:
                record["purposes"].append(purpose)

    @classmethod
    def _add_expo_declarations(
        cls,
        context: ReactNativeScanExtractionContext,
        records: dict[tuple[str, str], dict[str, Any]],
    ) -> set[str]:
        expo = context.mapping(context.source_metadata.get("expo"))
        android = context.mapping(expo.get("android"))
        blocked = {cls._android_permission(value) for value in context.string_list(android.get("blocked_permissions"))}
        blocked.discard("")
        for permission in blocked:
            cls._record(records, "Android", permission)["blocks"].append("Expo android.blockedPermissions")
        for value in context.string_list(android.get("permissions")):
            permission = cls._android_permission(value)
            if permission and permission not in blocked:
                cls._record(records, "Android", permission)["declarations"].append("Expo android.permissions")

        ios = context.mapping(expo.get("ios"))
        for key, value in context.mapping(ios.get("info_plist")).items():
            permission = str(key).strip()
            if not permission.endswith("UsageDescription"):
                continue
            record = cls._record(records, "iOS", permission)
            record["declarations"].append("Expo ios.infoPlist")
            purpose = context.first_non_empty(value)
            if purpose:
                record["purposes"].append(purpose)

        for plugin in context.mapping_list(expo.get("plugins")):
            name = context.first_non_empty(plugin.get("name"))
            for permission in cls.EXPO_PLUGIN_PERMISSIONS.get(name, ()):
                cls._record(records, "Android/iOS", permission)["inferences"].append(f"Expo plugin: {name}")
        return blocked

    @classmethod
    def _add_runtime_requests(
        cls,
        context: ReactNativeScanExtractionContext,
        records: dict[tuple[str, str], dict[str, Any]],
        blocked: set[str],
    ) -> None:
        for finding in context.opengrep_results_for_scope("react_native"):
            rule_id = context.first_non_empty(finding.get("check_id"))
            kind = PERMISSION_INVENTORY_RULE_ID_TO_KEY.get(rule_id)
            if kind is None:
                continue
            extra = context.mapping(finding.get("extra"))
            line = context.first_non_empty(extra.get("lines"))
            location = cls._location(context, finding)
            if kind == "android_runtime_request":
                for match in cls.ANDROID_CONSTANT_PATTERN.finditer(line):
                    permission = cls._android_permission(match.group(1) or match.group(2))
                    record = cls._record(records, "Android", permission)
                    record["requests"].append(location)
                    record["blocked"] = permission in blocked
            elif kind == "cross_platform_runtime_request":
                for platform, constant in cls.CROSS_PLATFORM_PATTERN.findall(line):
                    permission = (
                        cls._android_permission(constant)
                        if platform == "ANDROID"
                        else cls.IOS_PERMISSION_KEYS.get(constant, constant)
                    )
                    cls._record(records, "Android" if platform == "ANDROID" else "iOS", permission)["requests"].append(
                        location
                    )
            elif kind == "expo_runtime_request":
                for module in cls.EXPO_REQUEST_PATTERN.findall(line):
                    for permission in cls.EXPO_MODULE_PERMISSIONS.get(module, ()):
                        cls._record(records, "Android/iOS", permission)["requests"].append(location)

    @staticmethod
    def _record(
        records: dict[tuple[str, str], dict[str, Any]],
        platform: str,
        permission: str,
    ) -> dict[str, Any]:
        return records.setdefault(
            (platform, permission),
            {
                "declarations": [],
                "requests": [],
                "inferences": [],
                "purposes": [],
                "blocks": [],
                "blocked": False,
            },
        )

    @staticmethod
    def _finalize(platform: str, permission: str, record: dict[str, Any]) -> dict[str, Any]:
        declarations = list(dict.fromkeys(record["declarations"]))
        requests = list(dict.fromkeys(value for value in record["requests"] if value))
        inferences = list(dict.fromkeys(record["inferences"]))
        purposes = list(dict.fromkeys(record["purposes"]))
        if record["blocked"] and requests:
            status = "Requested but Blocked"
        elif declarations and requests:
            status = "Declared and Requested"
        elif requests and inferences:
            status = "Requested and Inferred from Expo Plugin"
        elif requests:
            status = "Requested but Not Declared"
        elif declarations:
            status = "Declared Only"
        elif record["blocks"]:
            status = "Blocked by Expo Configuration"
        else:
            status = "Inferred from Expo Plugin"
        evidence = [*(f"Declared by {value}." for value in declarations)]
        evidence.extend(f"Requested at {value}." for value in requests)
        evidence.extend(f"Inferred from {value}." for value in inferences)
        evidence.extend(f"Blocked by {value}." for value in record["blocks"])
        return {
            "platform": platform,
            "permission": permission,
            "status": status,
            "info": ", ".join(requests),
            "usage_description": " ".join(purposes),
            "general_description": " ".join(evidence),
            "confidence": "High"
            if declarations and requests
            else "Low"
            if inferences and not declarations
            else "Medium",
        }

    @staticmethod
    def _android_permission(value: object) -> str:
        text = str(value or "").strip()
        if not text:
            return ""
        return text if "." in text else f"android.permission.{text}"

    @staticmethod
    def _location(context: ReactNativeScanExtractionContext, finding: dict[str, Any]) -> str:
        text = context.first_non_empty(finding.get("path"))
        if text:
            path = Path(text)
            if path.is_absolute():
                try:
                    text = path.relative_to(context.project_path).as_posix()
                except ValueError:
                    text = path.as_posix()
        line = context.mapping(finding.get("start")).get("line")
        return f"{text}:{line}" if text and line not in (None, "") else text
