"""Build Android resilience evidence."""

import re
from dataclasses import dataclass
from typing import Any

from domain.post_scan.utilities import first_non_empty


@dataclass
class ResilienceEvidenceBuilder:
    root_detection_missing: dict[str, Any]
    biometric_local_authentication_bypass_possible: dict[str, Any]

    ROOT_PATTERN = re.compile(r"(?i)(?:\bsu\b|busybox|supersu|magisk|test-keys|rootbeer|isrooted|rootcheck)")

    def __init__(self, loaded_outputs: dict[str, Any]) -> None:
        package_prefix = first_non_empty(
            (loaded_outputs.get("aapt2_identity") or {}).get("package_name"),
            (loaded_outputs.get("androguard_metadata") or {}).get("package"),
        ).replace(".", "/")
        api_calls = list(((loaded_outputs.get("androguard_api_calls") or {}).get("items") or []))
        root_hits = self._root_hits(loaded_outputs, package_prefix, api_calls)
        biometric = self._biometric_bypass(package_prefix, api_calls)
        self.root_detection_missing = {
            "present": not bool(root_hits),
            "evidence": "no_root_detection_signals_found" if not root_hits else ", ".join(root_hits[:5]),
            "details": root_hits[:10],
        }
        self.biometric_local_authentication_bypass_possible = biometric

    def _root_hits(self, loaded_outputs: dict[str, Any], prefix: str, calls: list[dict[str, Any]]) -> list[str]:
        api_hits = self._sites(
            calls,
            lambda item: (
                self._matches(item, prefix)
                and self.ROOT_PATTERN.search(f"{self._callee(item)} {self._caller(item)}") is not None
            ),
        )
        string_hits: list[str] = []
        for item in (loaded_outputs.get("androguard_strings") or {}).get("items") or []:
            if not isinstance(item, dict) or not self.ROOT_PATTERN.search(first_non_empty(item.get("value"))):
                continue
            string_hits.extend(
                first_non_empty(xref.get("signature"))
                for xref in item.get("xrefs") or []
                if isinstance(xref, dict) and prefix in first_non_empty(xref.get("signature")).replace(".", "/")
            )
        return self._dedupe([*api_hits, *string_hits])

    def _biometric_bypass(self, prefix: str, calls: list[dict[str, Any]]) -> dict[str, Any]:
        biometric = self._sites(
            calls,
            lambda item: (
                self._matches(item, prefix)
                and any(
                    token in self._callee(item).lower()
                    for token in ("biometricprompt", "fingerprintmanager", "fingerprint")
                )
            ),
        )
        hardening = self._sites(
            calls,
            lambda item: (
                self._matches(item, prefix)
                and any(
                    token in self._callee(item).lower()
                    for token in ("cryptoobject", "setuserauthenticationrequired", "keygenparameterspec")
                )
            ),
        )
        if biometric and not hardening:
            return {"present": True, "evidence": biometric[0], "details": biometric[:10]}
        if biometric:
            return {"present": False, "evidence": hardening[0], "details": hardening[:10]}
        return {"present": False, "evidence": "no_biometric_authentication_flow_detected"}

    def _sites(self, calls: list[dict[str, Any]], predicate: Any) -> list[str]:
        return self._dedupe(
            [self._caller(item) for item in calls if isinstance(item, dict) and predicate(item) and self._caller(item)]
        )

    @staticmethod
    def _callee(item: dict[str, Any]) -> str:
        callee = item.get("callee") or {}
        return first_non_empty(callee.get("signature"), callee.get("class_name"), callee.get("method_name"))

    @staticmethod
    def _caller(item: dict[str, Any]) -> str:
        caller = item.get("caller") or {}
        return first_non_empty(caller.get("signature"), caller.get("class_name"), caller.get("method_name"))

    def _matches(self, item: dict[str, Any], prefix: str) -> bool:
        return bool(prefix and prefix in self._caller(item).replace(".", "/"))

    @staticmethod
    def _dedupe(values: list[str]) -> list[str]:
        return list(dict.fromkeys(value for value in values if value))
