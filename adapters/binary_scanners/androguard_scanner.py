"""Androguard scanner adapter for Android APK evidence extraction."""

from __future__ import annotations

import hashlib
import json
import re
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from xml.etree import ElementTree

from domain.models import ScanConfig, ScanResult, ScanType
from ports.scanner_port import ScannerPort
from utilities.apk_utils import is_apk_file

ANDROID_XML_NAMESPACE = "http://schemas.android.com/apk/res/android"


@dataclass(frozen=True)
class AndroguardScanContext:
    apk_path: Path
    apk: Any
    dex_objects: list[Any]
    analysis: Any


class AndroguardScanner(ScannerPort):
    """Scanner for structured Android security evidence extraction."""

    MAX_STRING_XREFS = 5
    STRING_PATTERNS = {
        "url": re.compile(r"https?://[^\s\"'<>]+", re.IGNORECASE),
        "domain": re.compile(
            r"\b[a-z0-9][a-z0-9.-]*\."
            r"(?:com|net|org|io|dev|app|co|gov|edu|cloud|info|biz)\b",
            re.IGNORECASE,
        ),
        "ip_address": re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"),
        "jwt": re.compile(r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b"),
        "api_key": re.compile(
            r"(?i)(api[_-]?key|apikey|client[_-]?secret|secret[_-]?key)"
        ),
        "token": re.compile(
            r"(?i)(access[_-]?token|auth[_-]?token|bearer|oauth|\btoken=)"
        ),
        "firebase": re.compile(r"(?i)(firebase|googleapis\.com|gcm|fcm)"),
        "cloud_provider": re.compile(
            r"(?i)(amazonaws\.com|s3\.|azure|blob\.core\.windows\.net|"
            r"cloudfront|storage\.googleapis)"
        ),
        "auth": re.compile(
            r"(?i)(password|passwd|credential|login|signin|auth|session)"
        ),
        "environment_marker": re.compile(
            r"(?i)(debug|staging|stage|dev|qa|prod|production|sandbox)"
        ),
        "filesystem_path": re.compile(
            r"(?i)(/data/|/sdcard/|/storage/|/system/|content://|file://)"
        ),
        "sql": re.compile(
            r"(?i)(\bselect\b.+\bfrom\b|\binsert\s+into\b|"
            r"\bupdate\b.+\bset\b|\bdelete\s+from\b|\bpragma\b|\bsqlite\b)"
        ),
        "reflection": re.compile(
            r"(?i)(forName|getMethod|getDeclaredMethod|invoke|reflect)"
        ),
        "dynamic_loading": re.compile(
            r"(?i)(DexClassLoader|PathClassLoader|loadLibrary|loadClass|System\.load)"
        ),
    }
    SENSITIVE_API_PATTERNS = {
        "webview": re.compile(r"Landroid/webkit/WebView;|Landroid/webkit/WebSettings;"),
        "crypto": re.compile(
            r"Ljavax/crypto/|Ljava/security/MessageDigest;|"
            r"Ljava/security/SecureRandom;"
        ),
        "tls": re.compile(
            r"Ljavax/net/ssl/|HostnameVerifier|TrustManager|X509TrustManager"
        ),
        "reflection": re.compile(
            r"Ljava/lang/reflect/|Ljava/lang/Class;->forName|->getMethod|"
            r"->getDeclaredMethod"
        ),
        "dynamic_loading": re.compile(
            r"DexClassLoader|PathClassLoader|Ljava/lang/System;->load|"
            r"Ljava/lang/Runtime;->load"
        ),
        "logging": re.compile(r"Landroid/util/Log;|Ljava/lang/System;->out"),
        "storage": re.compile(
            r"getSharedPreferences|Landroid/content/SharedPreferences;|"
            r"openFileOutput|Landroid/database/sqlite/"
        ),
        "runtime_exec": re.compile(
            r"Ljava/lang/Runtime;->exec|Ljava/lang/ProcessBuilder;"
        ),
        "networking": re.compile(r"Ljava/net/|Lokhttp3/|Lretrofit2/|Lorg/apache/http/"),
        "biometrics": re.compile(r"BiometricPrompt|FingerprintManager"),
        "permissions": re.compile(
            r"checkSelfPermission|requestPermissions|checkCallingPermission"
        ),
        "location": re.compile(r"Landroid/location/|FusedLocationProviderClient"),
        "keystore": re.compile(
            r"KeyStore|KeyGenParameterSpec|Landroid/security/keystore/"
        ),
    }

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
            ("metadata.json", self._extract_metadata),
            ("manifest.json", self._extract_manifest),
            ("permissions.json", self._extract_permissions),
            ("components.json", self._extract_components),
            ("strings.json", self._extract_strings),
            ("api_calls.json", self._extract_api_calls),
            ("xrefs.json", self._extract_xrefs),
            ("native_libs.json", self._extract_native_libs),
            ("assets.json", self._extract_assets),
            ("certificates.json", self._extract_certificates),
            ("files.json", self._extract_files),
            ("findings.json", self._extract_findings),
        ]

    def _extract_metadata(
        self, androguard_context: AndroguardScanContext
    ) -> dict[str, Any]:
        apk = androguard_context.apk
        apk_path = androguard_context.apk_path
        return {
            "apk_path": str(apk_path),
            "file_name": apk_path.name,
            "package": self._call(apk, "get_package"),
            "app_name": self._call(apk, "get_app_name"),
            "version_code": self._call(apk, "get_androidversion_code"),
            "version_name": self._call(apk, "get_androidversion_name"),
            "min_sdk": self._call(apk, "get_min_sdk_version"),
            "target_sdk": self._call(apk, "get_target_sdk_version"),
            "framework_indicators": self._framework_indicators(apk_path),
        }

    def _extract_manifest(
        self, androguard_context: AndroguardScanContext
    ) -> dict[str, Any]:
        manifest = self._call(androguard_context.apk, "get_android_manifest_xml")
        if manifest is None:
            return {"manifest": None, "xml": ""}
        return {
            "manifest": self._element_to_dict(manifest),
            "xml": ElementTree.tostring(manifest, encoding="unicode"),
        }

    def _extract_permissions(
        self, androguard_context: AndroguardScanContext
    ) -> dict[str, Any]:
        apk = androguard_context.apk
        return {
            "requested": sorted(self._call(apk, "get_permissions", []) or []),
            "declared": sorted(
                (self._call(apk, "get_declared_permissions", {}) or {}).keys()
            ),
        }

    def _extract_components(
        self, androguard_context: AndroguardScanContext
    ) -> dict[str, Any]:
        apk = androguard_context.apk
        manifest = self._call(apk, "get_android_manifest_xml")
        return {
            "main_activity": self._call(apk, "get_main_activity"),
            "activities": self._component_records(
                apk, manifest, "activity", self._call(apk, "get_activities", []) or []
            ),
            "services": self._component_records(
                apk, manifest, "service", self._call(apk, "get_services", []) or []
            ),
            "receivers": self._component_records(
                apk, manifest, "receiver", self._call(apk, "get_receivers", []) or []
            ),
            "providers": self._component_records(
                apk, manifest, "provider", self._call(apk, "get_providers", []) or []
            ),
        }

    def _extract_strings(
        self, androguard_context: AndroguardScanContext
    ) -> dict[str, Any]:
        analysis = androguard_context.analysis
        items: list[dict[str, Any]] = []
        for string_analysis in analysis.get_strings():
            value = string_analysis.get_value()
            categories = self._string_categories(value)
            if not categories:
                continue
            xrefs = [
                self._method_context(class_analysis, method_analysis)
                for class_analysis, method_analysis in list(
                    string_analysis.get_xref_from()
                )[: self.MAX_STRING_XREFS]
            ]
            items.append(
                {
                    "value": value,
                    "categories": categories,
                    "xrefs": xrefs,
                    "xref_count": len(list(string_analysis.get_xref_from())),
                }
            )
        return {"items": sorted(items, key=lambda item: item["value"])}

    def _extract_api_calls(
        self, androguard_context: AndroguardScanContext
    ) -> dict[str, Any]:
        items: list[dict[str, Any]] = []
        for caller in androguard_context.analysis.get_methods():
            if caller.is_external():
                continue
            for _class_analysis, callee, offset in caller.get_xref_to():
                categories = self._api_categories(callee)
                if not categories:
                    continue
                items.append(
                    {
                        "categories": categories,
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

    def _extract_xrefs(
        self, androguard_context: AndroguardScanContext
    ) -> dict[str, Any]:
        items: list[dict[str, Any]] = []
        for string_analysis in androguard_context.analysis.get_strings():
            value = string_analysis.get_value()
            categories = self._string_categories(value)
            if not categories:
                continue
            for class_analysis, method_analysis in list(
                string_analysis.get_xref_from()
            )[: self.MAX_STRING_XREFS]:
                items.append(
                    {
                        "relationship": "STRING_TO_METHOD",
                        "categories": categories,
                        "source": {"type": "string", "value": value},
                        "target": self._method_context(class_analysis, method_analysis),
                    }
                )

        for caller in androguard_context.analysis.get_methods():
            if caller.is_external():
                continue
            for _class_analysis, callee, offset in caller.get_xref_to():
                categories = self._api_categories(callee)
                if not categories:
                    continue
                for category in categories:
                    items.append(
                        {
                            "relationship": self._api_relationship(category),
                            "categories": [category],
                            "source": self._method_context_from_analysis(caller),
                            "target": self._method_context_from_analysis(callee),
                            "offset": offset,
                        }
                    )

        return {
            "items": sorted(
                items,
                key=lambda item: (
                    item["relationship"],
                    str(item["source"]),
                    str(item["target"]),
                ),
            )
        }

    def _extract_native_libs(
        self, androguard_context: AndroguardScanContext
    ) -> dict[str, Any]:
        return {
            "items": [
                name
                for name in self._apk_names(androguard_context.apk_path)
                if name.startswith("lib/") and name.endswith(".so")
            ]
        }

    def _extract_assets(
        self, androguard_context: AndroguardScanContext
    ) -> dict[str, Any]:
        return {
            "items": [
                name
                for name in self._apk_names(androguard_context.apk_path)
                if name.startswith("assets/")
            ]
        }

    def _extract_certificates(
        self, androguard_context: AndroguardScanContext
    ) -> dict[str, Any]:
        apk = androguard_context.apk
        schemes = {
            "all": "get_certificates",
            "v1": "get_certificates_v1",
            "v2": "get_certificates_v2",
            "v3": "get_certificates_v3",
        }
        return {
            scheme: [
                self._certificate_record(certificate)
                for certificate in self._call(apk, method_name, []) or []
            ]
            for scheme, method_name in schemes.items()
        }

    def _extract_files(
        self, androguard_context: AndroguardScanContext
    ) -> dict[str, Any]:
        return {"items": self._apk_names(androguard_context.apk_path)}

    def _extract_findings(
        self, androguard_context: AndroguardScanContext
    ) -> dict[str, Any]:
        findings: list[dict[str, Any]] = []
        permissions = set(
            self._call(androguard_context.apk, "get_permissions", []) or []
        )
        sensitive_permissions = sorted(
            permission
            for permission in permissions
            if permission
            in {
                "android.permission.READ_SMS",
                "android.permission.SEND_SMS",
                "android.permission.RECEIVE_SMS",
                "android.permission.READ_CONTACTS",
                "android.permission.WRITE_CONTACTS",
                "android.permission.ACCESS_FINE_LOCATION",
                "android.permission.ACCESS_COARSE_LOCATION",
                "android.permission.RECORD_AUDIO",
                "android.permission.CAMERA",
                "android.permission.READ_PHONE_STATE",
                "android.permission.WRITE_EXTERNAL_STORAGE",
            }
        )
        if sensitive_permissions:
            findings.append(
                self._finding(
                    finding_id="android-sensitive-permissions",
                    title="Sensitive Android permissions requested",
                    severity="medium",
                    confidence="high",
                    evidence=[{"permissions": sensitive_permissions}],
                    source_artifacts=["permissions.json"],
                    mappings={"masvs": ["MASVS-PLATFORM"], "cwe": [], "niap": []},
                )
            )

        attack_surface = self._component_attack_surface(androguard_context)
        if attack_surface:
            findings.append(
                self._finding(
                    finding_id="android-component-attack-surface",
                    title="Potentially exported Android components observed",
                    severity="medium",
                    confidence="medium",
                    evidence=attack_surface,
                    source_artifacts=["components.json", "manifest.json"],
                    mappings={"masvs": ["MASVS-PLATFORM"], "cwe": [], "niap": []},
                )
            )

        string_evidence = self._finding_string_evidence(androguard_context)
        for category, evidence in string_evidence.items():
            findings.append(
                self._finding(
                    finding_id=f"android-string-{category}",
                    title=f"Security-relevant {category} strings observed",
                    severity="low",
                    confidence="medium",
                    evidence=evidence,
                    source_artifacts=["strings.json", "xrefs.json"],
                    mappings={"masvs": ["MASVS-CODE"], "cwe": [], "niap": []},
                )
            )

        api_evidence = self._finding_api_evidence(androguard_context)
        severity_by_category = {
            "runtime_exec": "high",
            "dynamic_loading": "high",
            "tls": "medium",
            "webview": "medium",
            "crypto": "medium",
            "reflection": "medium",
            "networking": "low",
        }
        for category, evidence in api_evidence.items():
            findings.append(
                self._finding(
                    finding_id=f"android-api-{category}",
                    title=f"Sensitive {category} API usage observed",
                    severity=severity_by_category.get(category, "low"),
                    confidence="medium",
                    evidence=evidence,
                    source_artifacts=["api_calls.json", "xrefs.json"],
                    mappings={"masvs": ["MASVS-CODE"], "cwe": [], "niap": []},
                )
            )

        return {"items": sorted(findings, key=lambda item: item["id"])}

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
                success=True,
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

    def _build_report_summary(
        self,
        artifacts: dict[str, Any],
        errors: list[dict[str, str]],
    ) -> dict[str, Any]:
        metadata = artifacts.get("metadata.json", {})
        findings = artifacts.get("findings.json", {}).get("items", [])
        strings = artifacts.get("strings.json", {}).get("items", [])
        api_calls = artifacts.get("api_calls.json", {}).get("items", [])
        framework_indicators = metadata.get("framework_indicators", [])
        return {
            "artifact_count": len(artifacts),
            "error_count": len(errors),
            "package": metadata.get("package", ""),
            "app_name": metadata.get("app_name", ""),
            "version_name": metadata.get("version_name", ""),
            "target_sdk": metadata.get("target_sdk", ""),
            "finding_count": len(findings),
            "finding_severity_counts": self._count_values(
                finding.get("severity", "") for finding in findings
            ),
            "string_category_counts": self._count_values(
                category for item in strings for category in item.get("categories", [])
            ),
            "api_category_counts": self._count_values(
                category
                for item in api_calls
                for category in item.get("categories", [])
            ),
            "framework_indicators": framework_indicators,
            "analysis_limitations": [
                "Reflection and dynamic loading may hide runtime behavior.",
                "Encrypted strings and native code are not fully recoverable statically.",
                "Native libraries require separate native-code analysis.",
                "Runtime-only behavior is outside static analysis scope.",
            ],
        }

    def _empty_items(self, androguard_context: AndroguardScanContext) -> dict[str, Any]:
        return {"items": []}

    def _finding(
        self,
        finding_id: str,
        title: str,
        severity: str,
        confidence: str,
        evidence: list[dict[str, Any]],
        source_artifacts: list[str],
        mappings: dict[str, list[str]],
    ) -> dict[str, Any]:
        return {
            "id": finding_id,
            "title": title,
            "severity": severity,
            "confidence": confidence,
            "mappings": mappings,
            "evidence": evidence,
            "source_artifacts": source_artifacts,
        }

    def _finding_string_evidence(
        self, androguard_context: AndroguardScanContext
    ) -> dict[str, list[dict[str, Any]]]:
        categories_of_interest = {
            "api_key",
            "token",
            "jwt",
            "firebase",
            "cloud_provider",
            "auth",
        }
        evidence: dict[str, list[dict[str, Any]]] = {}
        for string_analysis in androguard_context.analysis.get_strings():
            value = string_analysis.get_value()
            categories = set(self._string_categories(value)) & categories_of_interest
            for category in categories:
                items = evidence.setdefault(category, [])
                if len(items) >= 5:
                    continue
                xrefs = list(string_analysis.get_xref_from())
                items.append(
                    {
                        "value": value,
                        "xref_count": len(xrefs),
                        "xrefs": [
                            self._method_context(class_analysis, method_analysis)
                            for class_analysis, method_analysis in xrefs[:2]
                        ],
                    }
                )
        return evidence

    def _finding_api_evidence(
        self, androguard_context: AndroguardScanContext
    ) -> dict[str, list[dict[str, Any]]]:
        categories_of_interest = {
            "runtime_exec",
            "dynamic_loading",
            "tls",
            "webview",
            "crypto",
            "reflection",
            "networking",
        }
        evidence: dict[str, list[dict[str, Any]]] = {}
        for caller in androguard_context.analysis.get_methods():
            if caller.is_external():
                continue
            for _class_analysis, callee, offset in caller.get_xref_to():
                categories = set(self._api_categories(callee)) & categories_of_interest
                for category in categories:
                    items = evidence.setdefault(category, [])
                    if len(items) >= 5:
                        continue
                    items.append(
                        {
                            "caller": self._method_context_from_analysis(caller),
                            "callee": self._method_context_from_analysis(callee),
                            "offset": offset,
                        }
                    )
        return evidence

    def _component_attack_surface(
        self, androguard_context: AndroguardScanContext
    ) -> list[dict[str, Any]]:
        apk = androguard_context.apk
        manifest = self._call(apk, "get_android_manifest_xml")
        evidence: list[dict[str, Any]] = []
        component_getters = {
            "activity": "get_activities",
            "service": "get_services",
            "receiver": "get_receivers",
            "provider": "get_providers",
        }
        for component_type, getter_name in component_getters.items():
            for name in self._call(apk, getter_name, []) or []:
                record = self._component_record(apk, manifest, component_type, name)
                exported = record["exported"]
                if exported is None:
                    exported = record["has_intent_filters"]
                if not exported:
                    continue
                evidence.append(
                    {
                        "type": component_type,
                        "name": name,
                        "exported": record["exported"],
                        "implicitly_exported": record["exported"] is None
                        and record["has_intent_filters"],
                        "permission": record["permission"],
                        "has_intent_filters": record["has_intent_filters"],
                        "intent_filters": record["intent_filters"],
                    }
                )
        return sorted(evidence, key=lambda item: (item["type"], item["name"]))

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
        list_lengths = [
            len(value) for value in payload.values() if isinstance(value, list)
        ]
        if list_lengths:
            return sum(list_lengths)
        return 0

    def _count_values(self, values: Any) -> dict[str, int]:
        counts: dict[str, int] = {}
        for value in values:
            if not value:
                continue
            counts[str(value)] = counts.get(str(value), 0) + 1
        return dict(sorted(counts.items()))

    def _string_categories(self, value: str) -> list[str]:
        if len(value.strip()) < 4:
            return []
        return [
            category
            for category, pattern in self.STRING_PATTERNS.items()
            if pattern.search(value)
        ]

    def _api_categories(self, method_analysis: Any) -> list[str]:
        signature = str(getattr(method_analysis, "full_name", ""))
        method = getattr(method_analysis, "method", None)
        if method is not None:
            signature = str(method)
        return [
            category
            for category, pattern in self.SENSITIVE_API_PATTERNS.items()
            if pattern.search(signature)
        ]

    def _api_relationship(self, category: str) -> str:
        relationship_names = {
            "dynamic_loading": "METHOD_TO_DYNAMIC_LOADING",
            "reflection": "METHOD_TO_REFLECTION",
            "networking": "METHOD_TO_NETWORKING",
        }
        return relationship_names.get(category, "METHOD_TO_SENSITIVE_API")

    def _method_context(
        self, class_analysis: Any, method_analysis: Any
    ) -> dict[str, str]:
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

    def _component_records(
        self,
        apk: Any,
        manifest: ElementTree.Element | None,
        component_type: str,
        component_names: list[str],
    ) -> list[dict[str, Any]]:
        return [
            self._component_record(apk, manifest, component_type, name)
            for name in sorted(component_names)
        ]

    def _component_record(
        self,
        apk: Any,
        manifest: ElementTree.Element | None,
        component_type: str,
        name: str,
    ) -> dict[str, Any]:
        intent_filters = apk.get_intent_filters(component_type, name) or {}
        return {
            "name": name,
            "exported": self._boolean_manifest_value(
                self._manifest_component_attribute(
                    apk, manifest, component_type, name, "exported"
                )
            ),
            "permission": self._manifest_component_attribute(
                apk, manifest, component_type, name, "permission"
            ),
            "has_intent_filters": any(intent_filters.values()),
            "intent_filters": intent_filters,
        }

    def _manifest_component_attribute(
        self,
        apk: Any,
        manifest: ElementTree.Element | None,
        component_type: str,
        component_name: str,
        attribute_name: str,
    ) -> str | None:
        if manifest is None:
            return None

        application = manifest.find("application")
        if application is None:
            return None

        package_name = str(self._call(apk, "get_package"))
        target_name = self._normalize_component_name(package_name, component_name)
        android_name = f"{{{ANDROID_XML_NAMESPACE}}}name"
        android_attribute = f"{{{ANDROID_XML_NAMESPACE}}}{attribute_name}"

        for element in application.findall(component_type):
            raw_name = element.get(android_name)
            normalized_name = self._normalize_component_name(package_name, raw_name)
            if normalized_name == target_name:
                return element.get(android_attribute)

        return None

    @staticmethod
    def _normalize_component_name(package_name: str, component_name: str | None) -> str:
        if not component_name:
            return ""
        if component_name.startswith("."):
            return f"{package_name}{component_name}"
        if "." not in component_name:
            return f"{package_name}.{component_name}"
        return component_name

    def _boolean_manifest_value(self, value: Any) -> bool | None:
        if value is None:
            return None
        if isinstance(value, bool):
            return value
        normalized = str(value).strip().lower()
        if normalized == "true":
            return True
        if normalized == "false":
            return False
        return None

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

    def _element_to_dict(self, element: ElementTree.Element) -> dict[str, Any]:
        children = list(element)
        grouped_children: dict[str, list[dict[str, Any]]] = {}
        for child in children:
            grouped_children.setdefault(child.tag, []).append(self._element_to_dict(child))

        child_payload: dict[str, Any] = {}
        for tag, items in grouped_children.items():
            child_payload[tag] = items[0] if len(items) == 1 else items

        text = (element.text or "").strip()
        payload: dict[str, Any] = {
            "tag": element.tag,
            "attributes": dict(element.attrib),
        }
        if child_payload:
            payload["children"] = child_payload
        if text:
            payload["text"] = text
        return payload

    def _call(self, obj: Any, method_name: str, default: Any = "") -> Any:
        method = getattr(obj, method_name, None)
        if method is None:
            return default
        return method()

    def _apk_names(self, apk_path: Path) -> list[str]:
        with zipfile.ZipFile(apk_path, "r") as archive:
            return sorted(name for name in archive.namelist() if not name.endswith("/"))

    def _framework_indicators(self, apk_path: Path) -> list[dict[str, str]]:
        names = self._apk_names(apk_path)
        indicators: list[dict[str, str]] = []
        checks = {
            "flutter": "libflutter.so",
            "react_native": "libreactnativejni.so",
            "cordova": "cordova.js",
            "unity": "libunity.so",
            "xamarin": "libmonodroid.so",
        }
        for framework, marker in checks.items():
            if any(name.endswith(marker) for name in names):
                indicators.append({"framework": framework, "marker": marker})
        return indicators
