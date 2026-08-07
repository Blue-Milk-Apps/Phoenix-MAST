from dataclasses import dataclass
from typing import Any

from domain.post_scan.utilities import first_non_empty


@dataclass
class Application:
    debuggable: bool = False
    allow_backup: bool = False
    uses_cleartext_traffic: bool = False

    def __init__(self, loaded_outputs: dict[str, Any]):
        aapt2_application = loaded_outputs.get("aapt2_application") or {}
        apktool_manifest_summary = loaded_outputs.get("apktool_manifest_summary") or {}
        manifest_application = apktool_manifest_summary.get("application") or {}
        self.debuggable = first_non_empty(
            manifest_application.get("debuggable"),
            aapt2_application.get("debuggable"),
        )
        self.allow_backup = first_non_empty(
            manifest_application.get("allow_backup"),
            aapt2_application.get("allow_backup"),
        )
        self.uses_cleartext_traffic = first_non_empty(
            manifest_application.get("uses_cleartext_traffic"),
            aapt2_application.get("uses_cleartext_traffic"),
        )
