"""Builder for Android permission report details."""

from dataclasses import dataclass, field
from typing import Any

from domain.domain_utilities import first_non_empty
from domain.post_scan.post_scan_constants import ANDROID_PERMISSION_DESCRIPTIONS


@dataclass
class PermissionsBuilder:
    loaded_outputs: dict[str, Any]
    permissions: list[dict[str, str]] = field(init=False, default_factory=list)

    def __post_init__(self) -> None:
        declared = {
            str(item.get("value", "")).strip(): str((item.get("context") or {}).get("protection_level", "")).strip()
            for item in ((self.loaded_outputs.get("apktool_permissions") or {}).get("declared") or [])
        }
        for permission in (self.loaded_outputs.get("aapt2_permissions") or {}).get("permissions") or []:
            name = first_non_empty(permission.get("name"))
            if not name:
                continue
            level = first_non_empty(permission.get("protection_level_hint"))
            suffix = name.rsplit(".", 1)[-1].replace("_", " ").lower()
            description = ANDROID_PERMISSION_DESCRIPTIONS.get(name) or (
                f"Declared permission ({declared[name]})"
                if declared.get(name)
                else suffix[:1].upper() + suffix[1:] + "."
            )
            self.permissions.append(
                {
                    "permission": name,
                    "status": "dangerous" if level.lower() == "dangerous" else "normal",
                    "info": level.lower().replace("_", " "),
                    "usage_description": "",
                    "general_description": description,
                }
            )

    def build(self) -> list[dict[str, str]]:
        return self.permissions
