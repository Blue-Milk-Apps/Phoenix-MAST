from dataclasses import dataclass
from typing import Any

from domain.post_scan.utilities import coerce_bool_like, first_non_empty


@dataclass
class Application:
    debuggable: bool | None = None
    allow_backup: bool | None = None
    uses_cleartext_traffic: bool | None = None

    def __init__(self, loaded_outputs: dict[str, Any]):
        aapt2_application = loaded_outputs.get("aapt2_application") or {}
        apktool_manifest_summary = loaded_outputs.get("apktool_manifest_summary") or {}
        manifest_application = apktool_manifest_summary.get("application") or {}
        self.debuggable = coerce_bool_like(
            first_non_empty(
                aapt2_application.get("debuggable"),
                manifest_application.get("debuggable"),
            )
        )
        self.allow_backup = coerce_bool_like(
            first_non_empty(
                aapt2_application.get("allow_backup"),
                manifest_application.get("allow_backup"),
            )
        )
        self.uses_cleartext_traffic = coerce_bool_like(
            first_non_empty(
                aapt2_application.get("uses_cleartext_traffic"),
                manifest_application.get("uses_cleartext_traffic"),
            )
        )
