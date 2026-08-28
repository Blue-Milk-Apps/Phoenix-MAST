"""Build native Android data-storage evidence from source scan artifacts."""

from __future__ import annotations

from dataclasses import dataclass

from domain.post_scan.android.native.scan_extraction_context import NativeAndroidScanExtractionContext
from domain.post_scan.android.native.security_evidence import NativeAndroidEvidenceEntry, opengrep_entry
from domain.post_scan.android.rule_registry import REPORT_RULE_IDS_BY_SECTION


@dataclass
class NativeAndroidDataStorageEvidence:
    accesses_external_storage: NativeAndroidEvidenceEntry
    sensitive_information_stored_in_world_readable_or_writable_file_in_internal_storage: NativeAndroidEvidenceEntry
    sensitive_information_stored_in_external_storage: NativeAndroidEvidenceEntry
    assessed: bool

    EXTERNAL_STORAGE_PERMISSIONS = frozenset(
        {
            "android.permission.READ_EXTERNAL_STORAGE",
            "android.permission.WRITE_EXTERNAL_STORAGE",
            "android.permission.MANAGE_EXTERNAL_STORAGE",
            "android.permission.READ_MEDIA_AUDIO",
            "android.permission.READ_MEDIA_IMAGES",
            "android.permission.READ_MEDIA_VIDEO",
        }
    )

    def __init__(self, context: NativeAndroidScanExtractionContext) -> None:
        if context.manifest_permissions_assessed:
            declared = {context.first_non_empty(item.get("name")) for item in context.permissions}
            matches = sorted(declared & self.EXTERNAL_STORAGE_PERMISSIONS)
            self.accesses_external_storage = NativeAndroidEvidenceEntry(
                bool(matches),
                ", ".join(matches) if matches else "no_external_storage_permissions",
                matches,
            )
        else:
            self.accesses_external_storage = NativeAndroidEvidenceEntry(None)

        for evidence_key in REPORT_RULE_IDS_BY_SECTION["Data Storage"]:
            setattr(
                self,
                evidence_key,
                opengrep_entry(
                    context,
                    REPORT_RULE_IDS_BY_SECTION["Data Storage"][evidence_key],
                    f"no_{evidence_key}_hits",
                ),
            )
        self.assessed = any(
            entry.present is not None
            for name, entry in vars(self).items()
            if name != "assessed" and isinstance(entry, NativeAndroidEvidenceEntry)
        )
