"""Android Androguard scanner adapter for APK evidence extraction."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from domain.models import ScanConfig, ScanResult, ScanType
from ports.scanner_port import ScannerPort
from utilities.apk_utils import is_apk_file


@dataclass(frozen=True)
class AndroguardScanContext:
    apk_path: Path
    apk: Any
    dex_objects: list[Any]
    analysis: Any


class AndroguardScanner(ScannerPort):
    """Scanner for structured Android security evidence extraction."""

    MAX_STRING_XREFS = 5

    @property
    def scan_type(self) -> ScanType:
        return ScanType.ANDROGUARD

    @property
    def name(self) -> str:
        return "Androguard Android Evidence Scanner"

    @property
    def description(self) -> str:
        return "Structured Android security evidence extracted from one APK."

    def is_available(self) -> bool:
        try:
            from androguard.misc import AnalyzeAPK  # noqa: F401
        except ImportError:
            return False
        return True

    def scan(self, config: ScanConfig) -> list[ScanResult]:
        apk_path = config.project_path
        if not apk_path.is_file() or not is_apk_file(apk_path):
            return [
                ScanResult(
                    scanner_name=self.name,
                    scan_type=self.scan_type,
                    success=False,
                    skipped=True,
                    error_message="Androguard only runs on APK files.",
                )
            ]

        errors: list[dict[str, str]] = []
        try:
            apk, dex_objects, analysis = self._load_apk(apk_path)
        except ImportError:
            return [
                ScanResult(
                    scanner_name=self.name,
                    scan_type=self.scan_type,
                    success=False,
                    skipped=True,
                    error_message="Androguard is not installed.",
                )
            ]
        except Exception as exc:
            return [
                ScanResult(
                    scanner_name=self.name,
                    scan_type=self.scan_type,
                    success=False,
                    error_message=f"Androguard failed to load APK: {exc}",
                )
            ]

        androguard_context = AndroguardScanContext(
            apk_path=apk_path,
            apk=apk,
            dex_objects=dex_objects,
            analysis=analysis,
        )
        artifacts = self._extract_artifacts(androguard_context, errors)
        artifacts["errors.json"] = {"errors": errors}
        artifacts["report_summary.json"] = {}
        artifacts["scan_index.json"] = {}
        artifacts["report_summary.json"] = self._build_report_summary(artifacts, errors)
        artifacts["scan_index.json"] = self._build_scan_index(artifacts)
        return self._scan_results(artifacts)

    def _load_apk(self, apk_path: Path) -> tuple[Any, list[Any], Any]:
        self._suppress_androguard_logs()
        from androguard.misc import AnalyzeAPK

        apk, dex_objects, analysis = AnalyzeAPK(str(apk_path))
        if not isinstance(dex_objects, list):
            dex_objects = [dex_objects]
        return apk, dex_objects, analysis

    def _suppress_androguard_logs(self) -> None:
        try:
            from loguru import logger
        except ImportError:
            return
        logger.disable("androguard")

    def _extract_artifacts(
        self,
        androguard_context: AndroguardScanContext,
        errors: list[dict[str, str]],
    ) -> dict[str, Any]:
        artifacts: dict[str, Any] = {}
        for name, extractor in self._artifact_extractors():
            try:
                artifacts[name] = extractor(androguard_context)
            except Exception as exc:
                errors.append({"artifact": name, "error": str(exc)})
                artifacts[name] = {"items": [], "partial_failure": True}
        return artifacts

    def _artifact_extractors(self) -> list[tuple[str, Any]]:
        return [
            ("strings.json", self._extract_strings),
            ("api_calls.json", self._extract_api_calls),
            ("certificates.json", self._extract_certificates),
        ]

    def _extract_strings(self, androguard_context: AndroguardScanContext) -> dict[str, Any]:
        analysis = androguard_context.analysis
        items: list[dict[str, Any]] = []
        for string_analysis in analysis.get_strings():
            value = string_analysis.get_value()
            references = list(string_analysis.get_xref_from())
            xrefs = [
                self._method_context(class_analysis, method_analysis)
                for class_analysis, method_analysis in references[: self.MAX_STRING_XREFS]
            ]
            items.append(
                {
                    "value": value,
                    "xrefs": xrefs,
                    "xref_count": len(references),
                }
            )
        return {"items": sorted(items, key=lambda item: item["value"])}

    def _extract_api_calls(self, androguard_context: AndroguardScanContext) -> dict[str, Any]:
        items: list[dict[str, Any]] = []
        for caller in androguard_context.analysis.get_methods():
            if caller.is_external():
                continue
            for _class_analysis, callee, offset in caller.get_xref_to():
                items.append(
                    {
                        "caller": self._method_context_from_analysis(caller),
                        "callee": self._method_context_from_analysis(callee),
                        "offset": offset,
                    }
                )
        return {
            "items": sorted(
                items,
                key=lambda item: (
                    item["caller"]["signature"],
                    item["callee"]["signature"],
                    item["offset"],
                ),
            )
        }

    def _extract_certificates(self, androguard_context: AndroguardScanContext) -> dict[str, Any]:
        apk = androguard_context.apk
        schemes = {
            "all": "get_certificates",
            "v1": "get_certificates_v1",
            "v2": "get_certificates_v2",
            "v3": "get_certificates_v3",
        }
        return {
            scheme: [self._certificate_record(certificate) for certificate in self._call(apk, method_name, []) or []]
            for scheme, method_name in schemes.items()
        }

    def _scan_results(self, artifacts: dict[str, Any]) -> list[ScanResult]:
        ordered_names = [name for name, _extractor in self._artifact_extractors()] + [
            "report_summary.json",
            "scan_index.json",
            "errors.json",
        ]
        return [
            ScanResult(
                scanner_name=self.name,
                scan_type=self.scan_type,
                success=not artifacts.get("errors.json", {}).get("errors"),
                error_message="Androguard extraction was incomplete."
                if artifacts.get("errors.json", {}).get("errors")
                else "",
                raw_output=json.dumps(artifacts[name], indent=2, sort_keys=True) + "\n",
                description=self.description,
                relative_target_path=name,
            )
            for name in ordered_names
        ]

    def _build_scan_index(self, artifacts: dict[str, Any]) -> dict[str, Any]:
        return {
            "artifacts": [
                {
                    "name": name,
                    "item_count": self._scan_index_item_count(name, payload),
                    "partial_failure": bool(payload.get("partial_failure", False))
                    if isinstance(payload, dict)
                    else False,
                }
                for name, payload in sorted(artifacts.items())
            ]
        }

    def _build_report_summary(self, artifacts: dict[str, Any], errors: list[dict[str, str]]) -> dict[str, Any]:
        return {
            "artifact_count": len(artifacts),
            "error_count": len(errors),
            "string_count": len(artifacts.get("strings.json", {}).get("items", [])),
            "api_call_count": len(artifacts.get("api_calls.json", {}).get("items", [])),
        }

    def _scan_index_item_count(self, name: str, payload: Any) -> int:
        if name in {"report_summary.json", "scan_index.json"}:
            return 0
        return self._count_records_in_output(payload)

    def _count_records_in_output(self, payload: Any) -> int:
        if not isinstance(payload, dict):
            return 0
        items = payload.get("items")
        if isinstance(items, list):
            return len(items)
        list_lengths = [len(value) for value in payload.values() if isinstance(value, list)]
        if list_lengths:
            return sum(list_lengths)
        return 0

    def _method_context(self, class_analysis: Any, method_analysis: Any) -> dict[str, str]:
        return {
            "class_name": str(getattr(class_analysis, "name", "")),
            "method_name": str(getattr(method_analysis, "name", "")),
            "descriptor": str(getattr(method_analysis, "descriptor", "")),
            "signature": str(getattr(method_analysis, "full_name", "")),
        }

    def _method_context_from_analysis(self, method_analysis: Any) -> dict[str, str]:
        return {
            "class_name": str(getattr(method_analysis, "class_name", "")),
            "method_name": str(getattr(method_analysis, "name", "")),
            "descriptor": str(getattr(method_analysis, "descriptor", "")),
            "signature": str(getattr(method_analysis, "full_name", "")),
        }

    def _certificate_record(self, certificate: Any) -> dict[str, Any]:
        der_bytes = certificate.dump()
        return {
            "subject": self._native_or_text(getattr(certificate, "subject", "")),
            "issuer": self._native_or_text(getattr(certificate, "issuer", "")),
            "serial_number": str(getattr(certificate, "serial_number", "")),
            "not_valid_before": str(getattr(certificate, "not_valid_before", "")),
            "not_valid_after": str(getattr(certificate, "not_valid_after", "")),
            "sha1": hashlib.sha1(der_bytes).hexdigest(),
            "sha256": hashlib.sha256(der_bytes).hexdigest(),
        }

    def _native_or_text(self, value: Any) -> Any:
        native = getattr(value, "native", None)
        if native is not None:
            return native
        return str(value)

    def _call(self, obj: Any, method_name: str, default: Any = "") -> Any:
        method = getattr(obj, method_name, None)
        if method is None:
            return default
        return method()
