"""Build native Android source functionality evidence."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from domain.post_scan.android.functionality import Functionality
from domain.post_scan.android.native.scan_extraction_context import NativeAndroidScanExtractionContext


@dataclass
class NativeAndroidFunctionality:
    items: dict[str, dict[str, Any]]
    assessed: bool

    def __init__(self, context: NativeAndroidScanExtractionContext) -> None:
        self.assessed = context.manifest_permissions_assessed or context.opengrep_assessed
        if not self.assessed:
            self.items = {
                key: {
                    "present": None,
                    "explanation": "Functionality was not assessed because source evidence was unavailable.",
                }
                for key in Functionality.KEYS
            }
            return

        declared_permissions = {context.first_non_empty(permission.get("name")) for permission in context.permissions}
        declared_permissions.discard("")
        permission_evidence = {
            key: sorted(names & declared_permissions)
            for key, names in Functionality.PERMISSIONS.items()
            if names & declared_permissions
        }
        opengrep_evidence: dict[str, list[str]] = {}
        if context.opengrep_assessed:
            for result in context.opengrep_results:
                capability = self._capability(result)
                if capability not in Functionality.KEYS:
                    continue
                explanation = self._result_explanation(result)
                if explanation:
                    opengrep_evidence.setdefault(capability, []).append(explanation)

        self.items = {}
        for capability in Functionality.KEYS:
            permissions = permission_evidence.get(capability, [])
            opengrep = list(dict.fromkeys(opengrep_evidence.get(capability, [])))
            present = bool(permissions or opengrep)
            self.items[capability] = {
                "present": present,
                "explanation": self._explanation(capability, permissions, opengrep),
            }

    @staticmethod
    def _phoenix_metadata(result: dict[str, Any]) -> dict[str, Any]:
        extra = result.get("extra") if isinstance(result.get("extra"), dict) else {}
        metadata = extra.get("metadata") if isinstance(extra.get("metadata"), dict) else {}
        phoenix = metadata.get("phoenix")
        return phoenix if isinstance(phoenix, dict) else {}

    @classmethod
    def _capability(cls, result: dict[str, Any]) -> str:
        rule_id = str(result.get("check_id", "")).strip()
        if rule_id in Functionality.RULE_IDS:
            return Functionality.RULE_IDS[rule_id]

        metadata = cls._phoenix_metadata(result)
        raw_check_id = metadata.get("check_id")
        try:
            check_id = int(raw_check_id)
        except (TypeError, ValueError):
            return ""
        if check_id == 60:
            title = str(metadata.get("title", "")).lower()
            return "Contacts" if "contact" in title else "Calendar" if "calendar" in title else ""
        return Functionality.CHECK_IDS.get(check_id, "")

    @classmethod
    def _result_explanation(cls, result: dict[str, Any]) -> str:
        metadata = cls._phoenix_metadata(result)
        extra = result.get("extra") if isinstance(result.get("extra"), dict) else {}
        return (
            str(metadata.get("description", "")).strip()
            or str(metadata.get("title", "")).strip()
            or str(extra.get("message", "")).strip()
            or cls._location(result)
            or f"OpenGrep rule {result.get('check_id', '')} matched."
        )

    @staticmethod
    def _location(result: dict[str, Any]) -> str:
        path = str(result.get("path", "")).strip()
        start = result.get("start") if isinstance(result.get("start"), dict) else {}
        line = start.get("line")
        return f"{path}:{line}" if path and line not in (None, "") else path

    @staticmethod
    def _explanation(capability: str, permissions: list[str], opengrep: list[str]) -> str:
        parts: list[str] = []
        if opengrep:
            parts.append("; ".join(opengrep))
        if permissions:
            noun = "permission" if len(permissions) == 1 else "permissions"
            parts.append(f"Declared {noun}: {', '.join(permissions)}.")
        if parts:
            return " ".join(parts)
        return f"No available source evidence indicated {capability.lower()} functionality."
