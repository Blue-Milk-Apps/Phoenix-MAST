"""Build Flutter functionality inventory from embedded-platform source evidence."""

from __future__ import annotations

from dataclasses import asdict, dataclass, fields
from pathlib import Path
from typing import Any

from domain.post_scan.android.functionality import Functionality as AndroidFunctionality
from domain.post_scan.flutter.scan_extraction_context import FlutterScanExtractionContext
from domain.post_scan.flutter.security_evidence import opengrep_scope_applicable
from domain.post_scan.ios.common.functionality import IOSFunctionality
from domain.report import AssessmentStatus


@dataclass
class FlutterFunctionality:
    items: dict[str, dict[str, Any]]
    platform_assessments: dict[str, dict[str, dict[str, Any]]]
    assessed: bool
    fully_assessed: bool

    CAPABILITIES = (
        *AndroidFunctionality.KEYS,
        "Biometric Authentication",
        "Keychain",
        "Nearby Interaction",
        "Push Notifications",
    )

    def __init__(self, context: FlutterScanExtractionContext) -> None:
        evidence: dict[str, list[str]] = {capability: [] for capability in self.CAPABILITIES}
        platform_evidence = {
            platform: {capability: [] for capability in self.CAPABILITIES} for platform in ("android", "ios")
        }
        self._add_android_permissions(context, evidence, platform_evidence)
        self._add_ios_metadata(context, evidence, platform_evidence)
        self._add_opengrep_findings(context, evidence, platform_evidence)

        applicable_platforms = {
            platform: opengrep_scope_applicable(context, platform) for platform in ("android", "ios")
        }
        platform_assessments = [
            all(
                self._platform_assessed(context, platform, capability)
                for capability in self._platform_capabilities(platform)
            )
            for platform, applicable in applicable_platforms.items()
            if applicable
        ]
        self.fully_assessed = bool(platform_assessments) and all(platform_assessments)
        self.items = {}
        self.platform_assessments = {}
        for capability in self.CAPABILITIES:
            details = list(dict.fromkeys(evidence[capability]))
            if details:
                self.items[capability] = {"present": True, "explanation": " ".join(details)}
            elif self._capability_assessed(context, capability, applicable_platforms):
                self.items[capability] = {
                    "present": False,
                    "explanation": f"No assessed source evidence indicated {capability.lower()} functionality.",
                }
            else:
                self.items[capability] = {
                    "present": None,
                    "explanation": "Functionality was not fully assessed for the applicable platforms.",
                }
            self.platform_assessments[capability] = self._platform_assessment_rows(
                context,
                capability,
                applicable_platforms,
                platform_evidence,
            )
        self.assessed = self.fully_assessed or any(item["present"] is True for item in self.items.values())

    @classmethod
    def _platform_assessment_rows(
        cls,
        context: FlutterScanExtractionContext,
        capability: str,
        applicable_platforms: dict[str, bool],
        platform_evidence: dict[str, dict[str, list[str]]],
    ) -> dict[str, dict[str, Any]]:
        rows: dict[str, dict[str, Any]] = {}
        for platform, applicable in applicable_platforms.items():
            if not applicable or capability not in cls._platform_capabilities(platform):
                continue
            details = list(dict.fromkeys(platform_evidence[platform][capability]))
            if details:
                rows[platform] = {
                    "status": AssessmentStatus.PRESENT.value,
                    "explanation": " ".join(details),
                    "evidence": details,
                }
                continue
            if not cls._platform_assessed(context, platform, capability):
                rows[platform] = {
                    "status": AssessmentStatus.NOT_EVALUATED.value,
                    "explanation": "Required platform scan evidence was unavailable.",
                    "evidence": [],
                }
                continue
            rows[platform] = {
                "status": AssessmentStatus.NOT_PRESENT.value,
                "explanation": f"No assessed {platform} source evidence indicated {capability.lower()} functionality.",
                "evidence": [],
            }
        return rows

    @classmethod
    def _capability_assessed(
        cls,
        context: FlutterScanExtractionContext,
        capability: str,
        applicable_platforms: dict[str, bool],
    ) -> bool:
        platforms = [
            platform
            for platform, applicable in applicable_platforms.items()
            if applicable and capability in cls._platform_capabilities(platform)
        ]
        return bool(platforms) and all(cls._platform_assessed(context, platform, capability) for platform in platforms)

    @classmethod
    def _platform_capabilities(cls, platform: str) -> frozenset[str]:
        if platform == "android":
            return frozenset(AndroidFunctionality.KEYS)
        if platform == "ios":
            return frozenset(field.name.replace("_", " ") for field in fields(IOSFunctionality))
        return frozenset()

    @classmethod
    def _platform_assessed(
        cls,
        context: FlutterScanExtractionContext,
        platform: str,
        capability: str,
    ) -> bool:
        if platform == "android":
            if not context.android_metadata_assessed or not isinstance(
                context.android_metadata.get("permissions"), list
            ):
                return False
            rule_ids = frozenset(
                rule_id for rule_id, name in AndroidFunctionality.RULE_IDS.items() if name == capability
            )
            return cls._rules_assessed(context, "android", rule_ids)

        if platform == "ios":
            if not context.ios_metadata_assessed or not isinstance(context.ios_metadata.get("permissions"), list):
                return False
            return True

        return False

    @staticmethod
    def _rules_assessed(
        context: FlutterScanExtractionContext,
        scope: str,
        rule_ids: frozenset[str],
    ) -> bool:
        return (
            bool(rule_ids)
            and context.opengrep_scope_assessed(scope)
            and rule_ids <= context.opengrep_configured_rule_ids(scope)
        )

    @staticmethod
    def _add_android_permissions(
        context: FlutterScanExtractionContext,
        evidence: dict[str, list[str]],
        platform_evidence: dict[str, dict[str, list[str]]],
    ) -> None:
        permissions = context.android_metadata.get("permissions")
        if not isinstance(permissions, list):
            return
        declared = {context.first_non_empty(item.get("name")) for item in permissions if isinstance(item, dict)}
        declared.discard("")
        for capability, names in AndroidFunctionality.PERMISSIONS.items():
            for permission in sorted(names & declared):
                detail = f"Declared Android permission: {permission}."
                evidence[capability].append(detail)
                platform_evidence["android"][capability].append(detail)

    @staticmethod
    def _add_ios_metadata(
        context: FlutterScanExtractionContext,
        evidence: dict[str, list[str]],
        platform_evidence: dict[str, dict[str, list[str]]],
    ) -> None:
        permissions = context.ios_metadata.get("permissions")
        permission_keys = (
            {context.first_non_empty(item.get("key")) for item in permissions if isinstance(item, dict)}
            if isinstance(permissions, list)
            else set()
        )
        permission_keys.discard("")
        model = IOSFunctionality(
            {"plist_outputs": {"platform": {"privacy": {"permissions": [{"key": key} for key in permission_keys]}}}}
        )
        for key, item in asdict(model).items():
            capability = key.replace("_", " ")
            if item["present"] and capability in evidence:
                evidence[capability].append(item["explanation"])
                platform_evidence["ios"][capability].append(item["explanation"])

        for artifact in context.ios_entitlements:
            metadata = artifact.get("metadata")
            if not isinstance(metadata, dict):
                continue
            for key, capability in (
                ("aps_environment", "Push Notifications"),
                ("healthkit", "Health Data"),
                ("in_app_payments", "Payment Services"),
                ("keychain_access_groups", "Keychain"),
            ):
                if FlutterFunctionality._has_value(metadata.get(key)):
                    detail = f"iOS entitlement {key} is present."
                    evidence[capability].append(detail)
                    platform_evidence["ios"][capability].append(detail)

        if "remote-notification" in context.ios_background_modes:
            detail = "iOS background mode remote-notification is declared."
            evidence["Push Notifications"].append(detail)
            platform_evidence["ios"]["Push Notifications"].append(detail)
        if context.ios_app_transport_security or any(context.ios_url_schemes.values()):
            detail = "iOS networking configuration is present."
            evidence["Networking"].append(detail)
            platform_evidence["ios"]["Networking"].append(detail)

    @classmethod
    def _add_opengrep_findings(
        cls,
        context: FlutterScanExtractionContext,
        evidence: dict[str, list[str]],
        platform_evidence: dict[str, dict[str, list[str]]],
    ) -> None:
        for scope, mapping in (("android", AndroidFunctionality.RULE_IDS),):
            for result in context.opengrep_results_for_scope(scope):
                capability = mapping.get(context.first_non_empty(result.get("check_id")))
                if capability not in evidence:
                    continue
                explanation = cls._result_explanation(context, result)
                if explanation:
                    evidence[capability].append(explanation)
                    if scope in platform_evidence:
                        platform_evidence[scope][capability].append(explanation)

    @staticmethod
    def _result_explanation(
        context: FlutterScanExtractionContext,
        result: dict[str, Any],
    ) -> str:
        extra = result.get("extra")
        extra = extra if isinstance(extra, dict) else {}
        metadata = extra.get("metadata")
        metadata = metadata if isinstance(metadata, dict) else {}
        phoenix = metadata.get("phoenix")
        phoenix = phoenix if isinstance(phoenix, dict) else {}
        description = context.first_non_empty(
            phoenix.get("description"),
            phoenix.get("title"),
            extra.get("message"),
            extra.get("lines"),
        )
        path_text = context.first_non_empty(result.get("path"))
        if path_text:
            path = Path(path_text)
            if path.is_absolute():
                try:
                    path_text = path.relative_to(context.project_path).as_posix()
                except ValueError:
                    path_text = path.as_posix()
        start = result.get("start")
        start = start if isinstance(start, dict) else {}
        line = start.get("line")
        location = f"{path_text}:{line}" if path_text and line not in (None, "") else path_text
        if description and location:
            return f"{description} ({location})."
        return f"{description or location}." if description or location else ""

    @staticmethod
    def _has_value(value: object) -> bool:
        if isinstance(value, bool):
            return value
        if isinstance(value, (list, tuple, set, dict, str)):
            return bool(value)
        return value is not None
