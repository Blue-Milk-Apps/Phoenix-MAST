"""Build native Android source manifest component counts."""

from __future__ import annotations

from dataclasses import dataclass

from domain.post_scan.android.native.scan_extraction_context import NativeAndroidScanExtractionContext


@dataclass
class NativeAndroidAppComponents:
    activities: int | None
    services: int | None
    receivers: int | None
    providers: int | None
    exported_activities: int | None
    exported_services: int | None
    exported_receivers: int | None
    exported_providers: int | None

    def __init__(self, context: NativeAndroidScanExtractionContext) -> None:
        source_components = context.source_metadata.get("components")
        if not isinstance(source_components, dict):
            self._set_unavailable()
            return

        self.activities, self.exported_activities = self._counts(source_components.get("activities"))
        self.services, self.exported_services = self._counts(source_components.get("services"))
        self.receivers, self.exported_receivers = self._counts(source_components.get("receivers"))
        self.providers, self.exported_providers = self._counts(source_components.get("providers"))

    def _set_unavailable(self) -> None:
        self.activities = None
        self.services = None
        self.receivers = None
        self.providers = None
        self.exported_activities = None
        self.exported_services = None
        self.exported_receivers = None
        self.exported_providers = None

    @staticmethod
    def _counts(value: object) -> tuple[int | None, int | None]:
        if not isinstance(value, list):
            return None, None
        components = [item for item in value if isinstance(item, dict)]
        exported = sum(1 for item in components if item.get("exported") is True)
        return len(components), exported
