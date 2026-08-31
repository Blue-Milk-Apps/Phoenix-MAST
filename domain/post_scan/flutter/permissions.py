"""Build platform-attributed Flutter permission details."""

from __future__ import annotations

from dataclasses import asdict, dataclass

from domain.post_scan.android.permissions import Permissions as AndroidPermissions
from domain.post_scan.flutter.scan_extraction_context import FlutterScanExtractionContext
from domain.post_scan.ios.common.permissions import PERMISSION_DETAILS as IOS_PERMISSION_DETAILS


@dataclass(frozen=True)
class FlutterPermission:
    platform: str
    permission: str
    status: str
    info: str
    usage_description: str
    general_description: str


@dataclass
class FlutterPermissions:
    entries: list[FlutterPermission]
    assessed_platforms: list[str]

    def __init__(self, context: FlutterScanExtractionContext) -> None:
        self.entries = []
        self.assessed_platforms = []
        self._add_android(context)
        self._add_ios(context)

    @property
    def items(self) -> list[dict[str, str]]:
        return [asdict(entry) for entry in self.entries]

    def _add_android(self, context: FlutterScanExtractionContext) -> None:
        permissions = context.android_metadata.get("permissions")
        if not isinstance(permissions, list):
            return
        self.assessed_platforms.append("android")
        seen: set[str] = set()
        for permission in permissions:
            if not isinstance(permission, dict):
                continue
            name = context.first_non_empty(permission.get("name"))
            if not name or name in seen:
                continue
            seen.add(name)
            self.entries.append(
                FlutterPermission(
                    platform="Android",
                    permission=name,
                    status="",
                    info="",
                    usage_description="",
                    general_description=self._android_description(name),
                )
            )

    def _add_ios(self, context: FlutterScanExtractionContext) -> None:
        permissions = context.ios_metadata.get("permissions")
        if not isinstance(permissions, list):
            return
        self.assessed_platforms.append("ios")
        seen: set[str] = set()
        for permission in permissions:
            if not isinstance(permission, dict):
                continue
            key = context.first_non_empty(permission.get("key"))
            if not key or key in seen:
                continue
            seen.add(key)
            details = IOS_PERMISSION_DETAILS.get(key, {})
            self.entries.append(
                FlutterPermission(
                    platform="iOS",
                    permission=key,
                    status=details.get("status", "normal"),
                    info=details.get("info", ""),
                    usage_description=context.first_non_empty(permission.get("purpose")),
                    general_description=details.get("general_description", ""),
                )
            )

    @staticmethod
    def _android_description(name: str) -> str:
        description = AndroidPermissions.ANDROID_PERMISSION_DESCRIPTIONS.get(name)
        if description:
            return description
        suffix = name.rsplit(".", 1)[-1].replace("_", " ").lower()
        return suffix[:1].upper() + suffix[1:] + "." if suffix else ""
