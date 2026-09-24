"""Build React Native functionality from embedded mobile-platform evidence."""

from __future__ import annotations

from dataclasses import asdict, dataclass, fields
from pathlib import Path
from typing import Any

from domain.post_scan.android.functionality import Functionality as AndroidFunctionality
from domain.post_scan.android.rule_registry import FUNCTIONALITY_RULE_IDS as ANDROID_FUNCTIONALITY_RULE_IDS
from domain.post_scan.ios.common.functionality import IOSFunctionality
from domain.post_scan.react_native.rule_registry import (
    FUNCTIONALITY_RULE_ID_TO_KEY as REACT_NATIVE_FUNCTIONALITY_RULES,
)
from domain.post_scan.react_native.scan_extraction_context import ReactNativeScanExtractionContext
from domain.report import AssessmentStatus


@dataclass
class ReactNativeFunctionality:
    items: dict[str, dict[str, Any]]
    platform_assessments: dict[str, dict[str, dict[str, Any]]]
    applicable: bool
    assessed: bool
    fully_assessed: bool

    CAPABILITIES = tuple(
        dict.fromkeys(
            (
                *AndroidFunctionality.KEYS,
                "Biometric Authentication",
                "Data Storage",
                "Keychain",
                "Nearby Interaction",
                "Navigation",
                "Push Notifications",
            )
        )
    )
    # Use native platform labels when a capability has an Android or iOS
    # counterpart in the scan. Keep React Native for capabilities that only
    # exist at the JavaScript/runtime layer, such as navigation.
    PLATFORM_BACKED_CAPABILITIES = frozenset(
        (*AndroidFunctionality.KEYS, *(field.name.replace("_", " ") for field in fields(IOSFunctionality)))
    )

    def __init__(self, context: ReactNativeScanExtractionContext) -> None:
        evidence: dict[str, list[str]] = {capability: [] for capability in self.CAPABILITIES}
        platform_evidence = {
            scope: {capability: [] for capability in self.CAPABILITIES} for scope in ("react_native", "android", "ios")
        }
        self._add_android_permissions(context, evidence, platform_evidence)
        self._add_ios_metadata(context, evidence, platform_evidence)
        self._add_react_native_dependencies(context, evidence, platform_evidence)
        self._add_opengrep_findings(context, evidence, platform_evidence)

        platform_assessments: list[bool] = []
        if context.opengrep_scope_applicable("react_native"):
            platform_assessments.append(
                context.opengrep_scope_assessed(
                    "react_native",
                    frozenset(REACT_NATIVE_FUNCTIONALITY_RULES),
                )
            )
        if self._platform_applicable(context, "android"):
            platform_assessments.append(
                isinstance(context.android_metadata.get("permissions"), list)
                and context.opengrep_scope_assessed("android", ANDROID_FUNCTIONALITY_RULE_IDS)
            )
        if self._platform_applicable(context, "ios"):
            platform_assessments.append(
                isinstance(context.ios_metadata.get("permissions"), list)
                and context.opengrep_scope_assessed("ios", frozenset())
            )

        self.applicable = bool(platform_assessments)
        self.fully_assessed = self.applicable and all(platform_assessments)
        self.items = {}
        self.platform_assessments = {}
        for capability in self.CAPABILITIES:
            details = list(dict.fromkeys(evidence[capability]))
            if details:
                self.items[capability] = {"present": True, "explanation": " ".join(details)}
            elif self.fully_assessed:
                self.items[capability] = {
                    "present": False,
                    "explanation": f"No assessed mobile source evidence indicated {capability.lower()} functionality.",
                }
            else:
                self.items[capability] = {
                    "present": None,
                    "explanation": "Functionality was not fully assessed for the applicable mobile platforms.",
                }
            self.platform_assessments[capability] = self._platform_assessment_rows(
                context,
                capability,
                platform_evidence,
            )
        self.assessed = self.fully_assessed or any(item["present"] is True for item in self.items.values())

    @classmethod
    def _platform_assessment_rows(
        cls,
        context: ReactNativeScanExtractionContext,
        capability: str,
        platform_evidence: dict[str, dict[str, list[str]]],
    ) -> dict[str, dict[str, Any]]:
        rows: dict[str, dict[str, Any]] = {}
        native_scopes = cls._evidence_scopes(context, capability)
        for scope in ("react_native", "android", "ios"):
            if scope == "react_native" and native_scopes != ("react_native",):
                continue
            if not cls._scope_applicable(context, scope) or capability not in cls._scope_capabilities(scope):
                continue
            details = list(dict.fromkeys(platform_evidence[scope][capability]))
            if details:
                rows[scope] = {
                    "status": AssessmentStatus.PRESENT.value,
                    "explanation": " ".join(details),
                    "evidence": details,
                }
                continue
            if not cls._scope_assessed(context, scope):
                rows[scope] = {
                    "status": AssessmentStatus.NOT_EVALUATED.value,
                    "explanation": "Required platform scan evidence was unavailable.",
                    "evidence": [],
                }
                continue
            rows[scope] = {
                "status": AssessmentStatus.NOT_PRESENT.value,
                "explanation": f"No assessed {scope.replace('_', ' ')} source evidence indicated {capability.lower()} functionality.",
                "evidence": [],
            }
        return rows

    @classmethod
    def _scope_capabilities(cls, scope: str) -> frozenset[str]:
        if scope == "react_native":
            return frozenset(REACT_NATIVE_FUNCTIONALITY_RULES.values())
        if scope == "android":
            return frozenset(AndroidFunctionality.KEYS)
        return frozenset((field.name.replace("_", " ") for field in fields(IOSFunctionality)))

    @classmethod
    def _evidence_scopes(cls, context: ReactNativeScanExtractionContext, capability: str) -> tuple[str, ...]:
        """Choose native labels for capabilities backed by native inventories."""

        if capability not in cls.PLATFORM_BACKED_CAPABILITIES:
            return ("react_native",)
        native_scopes = tuple(
            scope
            for scope in ("android", "ios")
            if cls._scope_applicable(context, scope) and capability in cls._scope_capabilities(scope)
        )
        return native_scopes or ("react_native",)

    @staticmethod
    def _scope_applicable(context: ReactNativeScanExtractionContext, scope: str) -> bool:
        if scope == "react_native":
            return context.opengrep_scope_applicable(scope)
        return ReactNativeFunctionality._platform_applicable(context, scope)

    @staticmethod
    def _scope_assessed(context: ReactNativeScanExtractionContext, scope: str) -> bool:
        if scope == "react_native":
            return context.opengrep_scope_assessed(scope, frozenset(REACT_NATIVE_FUNCTIONALITY_RULES))
        if scope == "android":
            return isinstance(context.android_metadata.get("permissions"), list) and context.opengrep_scope_assessed(
                scope, ANDROID_FUNCTIONALITY_RULE_IDS
            )
        return isinstance(context.ios_metadata.get("permissions"), list) and context.opengrep_scope_assessed(
            scope, frozenset()
        )

    @staticmethod
    def _platform_applicable(context: ReactNativeScanExtractionContext, scope: str) -> bool:
        platform = context.android if scope == "android" else context.ios
        return platform.get("available") is True or context.opengrep_scope_applicable(scope)

    @staticmethod
    def _add_react_native_dependencies(
        context: ReactNativeScanExtractionContext,
        evidence: dict[str, list[str]],
        platform_evidence: dict[str, dict[str, list[str]]],
    ) -> None:
        if not context.first_non_empty(
            context.runtime.get("react_native_constraint"),
            context.runtime.get("expo_constraint"),
        ):
            return
        declared = {context.first_non_empty(item.get("name")) for item in context.dependencies["declared"]}
        declared.discard("")
        dependency_capabilities = {
            "Data Storage": {
                "@react-native-async-storage/async-storage",
                "@tanstack/query-async-storage-persister",
                "expo-secure-store",
                "react-native-encrypted-storage",
                "react-native-mmkv",
            },
            "Navigation": {
                "@react-navigation/bottom-tabs",
                "@react-navigation/native",
                "expo-router",
                "react-native-navigation",
            },
            "Networking": {
                "@react-native-community/netinfo",
                "@tanstack/react-query",
                "axios",
                "expo-network",
            },
        }
        for capability, package_names in dependency_capabilities.items():
            for package_name in sorted(declared & package_names):
                detail = f"Declared React Native dependency: {package_name}."
                evidence[capability].append(detail)
                for scope in ReactNativeFunctionality._evidence_scopes(context, capability):
                    platform_evidence[scope][capability].append(detail)

    @staticmethod
    def _add_android_permissions(
        context: ReactNativeScanExtractionContext,
        evidence: dict[str, list[str]],
        platform_evidence: dict[str, dict[str, list[str]]],
    ) -> None:
        declared = {
            context.first_non_empty(item.get("name"))
            for item in context.mapping_list(context.android_metadata.get("permissions"))
        }
        declared.discard("")
        for capability, names in AndroidFunctionality.PERMISSIONS.items():
            for permission in sorted(names & declared):
                detail = f"Declared Android permission: {permission}."
                evidence[capability].append(detail)
                platform_evidence["android"][capability].append(detail)

    @staticmethod
    def _add_ios_metadata(
        context: ReactNativeScanExtractionContext,
        evidence: dict[str, list[str]],
        platform_evidence: dict[str, dict[str, list[str]]],
    ) -> None:
        permission_keys = {
            context.first_non_empty(item.get("key"))
            for item in context.mapping_list(context.ios_metadata.get("permissions"))
        }
        permission_keys.discard("")
        model = IOSFunctionality(
            {"plist_outputs": {"platform": {"privacy": {"permissions": [{"key": key} for key in permission_keys]}}}}
        )
        for key, item in asdict(model).items():
            capability = key.replace("_", " ")
            if item["present"] and capability in evidence:
                evidence[capability].append(item["explanation"])
                platform_evidence["ios"][capability].append(item["explanation"])

        for artifact in context.mapping_list(context.ios_metadata.get("entitlements")):
            metadata = context.mapping(artifact.get("metadata"))
            for key, capability in (
                ("aps_environment", "Push Notifications"),
                ("healthkit", "Health Data"),
                ("in_app_payments", "Payment Services"),
                ("keychain_access_groups", "Keychain"),
            ):
                if ReactNativeFunctionality._has_value(metadata.get(key)):
                    detail = f"iOS entitlement {key} is present."
                    evidence[capability].append(detail)
                    platform_evidence["ios"][capability].append(detail)

        if "remote-notification" in context.string_list(context.ios_metadata.get("background_modes")):
            detail = "iOS background mode remote-notification is declared."
            evidence["Push Notifications"].append(detail)
            platform_evidence["ios"]["Push Notifications"].append(detail)
        if context.mapping(context.ios_metadata.get("app_transport_security")) or context.mapping(
            context.ios_metadata.get("url_schemes")
        ):
            detail = "iOS networking configuration is present."
            evidence["Networking"].append(detail)
            platform_evidence["ios"]["Networking"].append(detail)

    @classmethod
    def _add_opengrep_findings(
        cls,
        context: ReactNativeScanExtractionContext,
        evidence: dict[str, list[str]],
        platform_evidence: dict[str, dict[str, list[str]]],
    ) -> None:
        for scope, mapping in (
            ("react_native", REACT_NATIVE_FUNCTIONALITY_RULES),
            ("android", AndroidFunctionality.RULE_IDS),
        ):
            for result in context.opengrep_results_for_scope(scope):
                capability = mapping.get(context.first_non_empty(result.get("check_id")))
                if capability not in evidence:
                    continue
                explanation = cls._result_explanation(context, result)
                if explanation:
                    evidence[capability].append(explanation)
                    target_scopes = cls._evidence_scopes(context, capability) if scope == "react_native" else (scope,)
                    for target_scope in target_scopes:
                        platform_evidence[target_scope][capability].append(explanation)

    @staticmethod
    def _result_explanation(context: ReactNativeScanExtractionContext, result: dict[str, Any]) -> str:
        extra = context.mapping(result.get("extra"))
        phoenix = context.mapping(context.mapping(extra.get("metadata")).get("phoenix"))
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
        start = context.mapping(result.get("start"))
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
