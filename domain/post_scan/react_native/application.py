"""Build embedded Android application configuration for React Native reports."""

from __future__ import annotations

from dataclasses import dataclass

from domain.post_scan.react_native.scan_extraction_context import ReactNativeScanExtractionContext


@dataclass
class ReactNativeApplication:
    debuggable: bool | None
    allow_backup: bool | None
    uses_cleartext_traffic: bool | None

    def __init__(self, context: ReactNativeScanExtractionContext) -> None:
        application = context.android_application
        self.debuggable = self._optional_bool(application.get("debuggable"))
        self.allow_backup = self._optional_bool(application.get("allow_backup"))
        self.uses_cleartext_traffic = self._optional_bool(application.get("uses_cleartext_traffic"))

    @staticmethod
    def _optional_bool(value: object) -> bool | None:
        return value if isinstance(value, bool) else None
