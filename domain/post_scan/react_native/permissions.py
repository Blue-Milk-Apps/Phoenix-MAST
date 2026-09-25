"""Collect declared native and Expo permissions without runtime inference."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from domain.post_scan.android.native.permissions import NativeAndroidPermissions
from domain.post_scan.react_native.scan_extraction_context import ReactNativeScanExtractionContext


@dataclass
class ReactNativePermissions:
    items: list[dict[str, Any]]

    DISCLAIMER = (
        "This React Native source assessment cannot determine the final permissions in the packaged "
        "application. The permissions shown are derived from available source, Expo configuration, and native "
        "project metadata; config plugins, native dependencies, build variants, and manifest merging can change "
        "the final Android or iOS permission set."
    )

    def __init__(self, context: ReactNativeScanExtractionContext) -> None:
        records: dict[tuple[str, str], dict[str, Any]] = {}
        self._add_native_declarations(context, records)
        self._add_expo_declarations(context, records)
        self.items = [
            self._finalize(platform, permission, record) for (platform, permission), record in records.items()
        ]
        self.items.sort(key=lambda item: (item["platform"], item["permission"]))

    @classmethod
    def _add_native_declarations(
        cls,
        context: ReactNativeScanExtractionContext,
        records: dict[tuple[str, str], dict[str, Any]],
    ) -> None:
        for item in NativeAndroidPermissions(context).items:
            permission = item["permission"]
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
    ) -> None:
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
                "purposes": [],
                "blocks": [],
            },
        )

    @staticmethod
    def _finalize(platform: str, permission: str, record: dict[str, Any]) -> dict[str, Any]:
        declarations = list(dict.fromkeys(record["declarations"]))
        purposes = list(dict.fromkeys(record["purposes"]))
        status = "Declared Only" if declarations else "Blocked by Expo Configuration"
        evidence = [*(f"Declared by {value}." for value in declarations)]
        evidence.extend(f"Blocked by {value}." for value in record["blocks"])
        return {
            "platform": platform,
            "permission": permission,
            "status": status,
            "info": "",
            "usage_description": " ".join(purposes),
            "general_description": " ".join(evidence),
        }

    @staticmethod
    def _android_permission(value: object) -> str:
        text = str(value or "").strip()
        if not text:
            return ""
        return text if "." in text else f"android.permission.{text}"
