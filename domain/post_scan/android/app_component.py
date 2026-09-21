from dataclasses import dataclass
from typing import Any


@dataclass
class AppComponent:
    activities: int = 0
    services: int = 0
    receivers: int = 0
    providers: int = 0
    exported_activities: int = 0
    exported_services: int = 0
    exported_receivers: int = 0
    exported_providers: int = 0

    def __init__(self, loaded_outputs: dict[str, Any]):
        androguard_components = loaded_outputs.get("androguard_components") or {}

        activities = androguard_components.get("activities") or []
        services = androguard_components.get("services") or []
        receivers = androguard_components.get("receivers") or []
        providers = androguard_components.get("providers") or []
        self.activities = len(activities)
        self.services = len(services)
        self.receivers = len(receivers)
        self.providers = len(providers)
        self.exported_activities = self.count_exported(activities)
        self.exported_services = self.count_exported(services)
        self.exported_receivers = self.count_exported(receivers)
        self.exported_providers = self.count_exported(providers)

    @staticmethod
    def count_exported(components: list[dict[str, Any]]) -> int:
        return sum(
            1
            for component in components
            if component.get("exported") is True
            or (component.get("exported") is None and bool(component.get("has_intent_filters")))
        )
