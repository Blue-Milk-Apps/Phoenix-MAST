"""Build Android data-storage evidence."""

import re
from dataclasses import dataclass
from typing import Any

from domain.post_scan.android.functionality_builder import FunctionalityBuilder
from domain.post_scan.android.hardcoded_values_builder import HardcodedValuesBuilder
from domain.post_scan.utilities import (
    api_call_caller_signature,
    api_call_signature,
    app_package_prefix,
    caller_matches_package,
    dedupe_preserve_order,
    first_non_empty,
    matching_api_call_sites,
)


@dataclass
class DataStorageEvidenceBuilder:
    accesses_external_storage: dict[str, Any]
    authentication_credentials_not_protected_with_android_keystore: dict[str, Any]
    sensitive_information_stored_in_world_readable_or_writable_file_in_internal_storage: dict[str, Any]
    sensitive_information_stored_in_external_storage: dict[str, Any]
    does_not_prevent_screen_capture_of_sensitive_information: dict[str, Any]

    STORAGE_CREDENTIAL_HINT_PATTERN = re.compile(
        r"(?i)(?:auth|credential|login|passw(?:or)?d|token|session|rememberme)"
    )
    PASSWORD_HINT_PATTERN = re.compile(r"(?i)(?:passw(?:or)?d|passwd|pwd|newpassword|passcode|credential|login|auth)")
    FLAG_SECURE_PATTERN = re.compile(r"(?i)\bflag_secure\b")
    WORLD_MODE_PATTERN = re.compile(r"(?i)mode_world_(?:readable|writable)")
    SENSITIVE_UI_HINT_PATTERN = re.compile(
        r"(?i)(?:login|logon|signin|signup|password|passcode|pin|account|transfer|statement|payment|auth|profile)"
    )
    EXTERNAL_STORAGE_PERMISSIONS = {
        "android.permission.READ_EXTERNAL_STORAGE",
        "android.permission.WRITE_EXTERNAL_STORAGE",
        "android.permission.MANAGE_EXTERNAL_STORAGE",
        "android.permission.READ_MEDIA_AUDIO",
        "android.permission.READ_MEDIA_IMAGES",
        "android.permission.READ_MEDIA_VIDEO",
        "android.permission.READ_MEDIA_VISUAL_USER_SELECTED",
    }

    def __init__(self, loaded_outputs: dict[str, Any], hardcoded_values: HardcodedValuesBuilder) -> None:
        aapt2_permissions = loaded_outputs.get("aapt2_permissions") or {}
        androguard_api_calls = loaded_outputs.get("androguard_api_calls") or {}

        declared_permissions = {
            first_non_empty(permission.get("name")) for permission in aapt2_permissions.get("permissions") or []
        }
        declared_permissions.discard("")

        external_storage_permissions = sorted(
            permission for permission in declared_permissions if permission in self.EXTERNAL_STORAGE_PERMISSIONS
        )

        api_call_items = list(androguard_api_calls.get("items") or [])
        external_storage_callers = matching_api_call_sites(
            api_call_items,
            lambda item: "externalstorage" in api_call_signature(item).replace("_", "").lower(),
        )
        shared_preferences_callers = matching_api_call_sites(
            api_call_items,
            lambda item: first_non_empty((item.get("callee") or {}).get("method_name")) == "getSharedPreferences",
        )
        credential_storage_callers = [
            caller for caller in shared_preferences_callers if self.STORAGE_CREDENTIAL_HINT_PATTERN.search(caller)
        ]

        accesses_external_storage_evidence = dedupe_preserve_order(
            [*external_storage_permissions, *external_storage_callers]
        )
        keystore = FunctionalityBuilder(loaded_outputs).items.get("Keystore") or {}
        keystore_present = bool(keystore.get("present"))

        authentication_credentials_present = None
        if credential_storage_callers and not keystore_present:
            authentication_credentials_present = True

        screen_capture_protection = self._detect_screen_capture_protection(loaded_outputs)
        world_readable_internal = self._detect_world_readable_internal_storage(api_call_items)
        sensitive_external_storage = self._detect_sensitive_external_storage(
            external_storage_callers,
            hardcoded_values=hardcoded_values,
        )

        self.accesses_external_storage = {
            "present": bool(accesses_external_storage_evidence),
            "evidence": ", ".join(accesses_external_storage_evidence),
        }
        self.authentication_credentials_not_protected_with_android_keystore = {
            "present": authentication_credentials_present,
            "evidence": ", ".join(dedupe_preserve_order(credential_storage_callers)),
        }
        self.sensitive_information_stored_in_world_readable_or_writable_file_in_internal_storage = (
            world_readable_internal
        )
        self.sensitive_information_stored_in_external_storage = sensitive_external_storage
        self.does_not_prevent_screen_capture_of_sensitive_information = screen_capture_protection

    def _detect_screen_capture_protection(self, loaded_outputs: dict[str, Any]) -> dict[str, Any]:
        package_prefix = app_package_prefix(loaded_outputs)
        api_calls = list(((loaded_outputs.get("androguard_api_calls") or {}).get("items") or []))
        strings_outputs = loaded_outputs.get("strings_outputs") or {}

        secure_flag_callers = matching_api_call_sites(
            api_calls,
            lambda item: caller_matches_package(item, package_prefix) and self._is_window_flag_api_call(item),
        )
        secure_flag_source_hits = self._matching_strings_output_sources(
            strings_outputs=strings_outputs,
            pattern=self.FLAG_SECURE_PATTERN,
            package_prefix=package_prefix,
        )
        sensitive_ui_classes = self._sensitive_ui_class_names(loaded_outputs, package_prefix)

        secure_hits = dedupe_preserve_order([*secure_flag_callers, *secure_flag_source_hits])
        if secure_hits:
            return {
                "present": False,
                "evidence": secure_hits[0],
                "details": secure_hits[:10],
            }

        if sensitive_ui_classes:
            listed = ", ".join(sensitive_ui_classes[:5])
            return {
                "present": True,
                "evidence": f"no FLAG_SECURE usage found in sensitive UI classes: {listed}",
                "details": sensitive_ui_classes[:10],
            }

        return {
            "present": None,
            "evidence": "",
        }

    def _detect_world_readable_internal_storage(self, api_calls: list[dict[str, Any]]) -> dict[str, Any]:
        world_mode_hits = matching_api_call_sites(
            api_calls,
            lambda item: (
                self.WORLD_MODE_PATTERN.search(api_call_signature(item)) is not None
                or self.WORLD_MODE_PATTERN.search(api_call_caller_signature(item)) is not None
            ),
        )
        if world_mode_hits:
            return {"present": True, "evidence": world_mode_hits[0], "details": world_mode_hits[:10]}
        if api_calls:
            return {"present": False, "evidence": "no_world_readable_internal_storage_hits"}
        return {"present": None, "evidence": ""}

    def _detect_sensitive_external_storage(
        self,
        external_storage_callers: list[str],
        *,
        hardcoded_values: HardcodedValuesBuilder,
    ) -> dict[str, Any]:
        sensitive_callers = [
            caller
            for caller in external_storage_callers
            if self.PASSWORD_HINT_PATTERN.search(caller) or self.SENSITIVE_UI_HINT_PATTERN.search(caller)
        ]
        if sensitive_callers:
            return {"present": True, "evidence": sensitive_callers[0], "details": sensitive_callers[:10]}
        secrets = hardcoded_values.secrets
        external_secret_hits = [secret for secret in secrets if "external" in str(secret.get("location", "")).lower()]
        if external_secret_hits:
            evidence = first_non_empty(
                external_secret_hits[0].get("location"),
                external_secret_hits[0].get("value"),
            )
            return {"present": True, "evidence": evidence, "details": external_secret_hits[:10]}
        if not external_storage_callers:
            return {"present": False, "evidence": "no_external_storage_sensitive_hits"}
        return {"present": None, "evidence": ""}

    @staticmethod
    def _is_window_flag_api_call(item: dict[str, Any]) -> bool:
        signature = api_call_signature(item).lower()
        method_name = first_non_empty((item.get("callee") or {}).get("method_name")).lower()
        if method_name not in {"addflags", "setflags"}:
            return False
        return "android/view/window" in signature or "layoutparams" in signature

    @staticmethod
    def _matching_strings_output_sources(
        *,
        strings_outputs: dict[str, str],
        pattern: re.Pattern[str],
        package_prefix: str,
    ) -> list[str]:
        matches: list[str] = []
        for source_name, content in strings_outputs.items():
            if pattern.search(content or "") is None:
                continue
            normalized_source = source_name.replace(".", "/")
            if package_prefix and package_prefix not in normalized_source:
                continue
            matches.append(f"strings/{source_name}")
        return dedupe_preserve_order(matches)

    def _sensitive_ui_class_names(self, loaded_outputs: dict[str, Any], package_prefix: str) -> list[str]:
        candidates: list[str] = []
        aapt2_identity = loaded_outputs.get("aapt2_identity") or {}
        main_activity = first_non_empty(aapt2_identity.get("launchable_activity"))
        if main_activity:
            candidates.append(main_activity)

        androguard_components = loaded_outputs.get("androguard_components") or {}
        for activity in androguard_components.get("activities") or []:
            if not isinstance(activity, dict):
                continue
            candidates.append(
                first_non_empty(
                    activity.get("name"),
                    activity.get("class_name"),
                )
            )

        sensitive: list[str] = []
        for candidate in candidates:
            text = str(candidate or "").strip()
            if not text:
                continue
            normalized = text.replace(".", "/")
            if package_prefix and package_prefix not in normalized:
                continue
            simple_name = normalized.rsplit("/", 1)[-1].split(";")[0]
            if self.SENSITIVE_UI_HINT_PATTERN.search(simple_name) and simple_name not in sensitive:
                sensitive.append(simple_name)
        return sensitive
