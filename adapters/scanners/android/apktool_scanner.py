"""Android Apktool scanner adapter for compact security evidence extraction."""

from __future__ import annotations

import hashlib
import json
import re
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from xml.etree import ElementTree

from domain.models import ScanConfig, ScanResult, ScanType
from ports.scanner_port import ScannerPort
from utilities.apk_utils import find_apk_in_directory, is_apk_file

ANDROID_NS = "{http://schemas.android.com/apk/res/android}"


@dataclass(frozen=True)
class ApktoolDecodeResult:
    decoded_root: Path
    exit_code: int
    stdout: str
    stderr: str
    apktool_version: str


class ApktoolScanner(ScannerPort):
    """Scanner for normalized Android evidence reconstructed by apktool."""

    DEFAULT_TIMEOUT_SECONDS = 300
    MAX_TEXT_FILE_BYTES = 512_000
    MAX_SMALI_FILES = 5000
    MAX_MATCHES_PER_CATEGORY = 250
    SECRET_CONTEXT_CHARS = 80

    CODE_PATTERNS = {
        "webview": re.compile(
            r"(Landroid/webkit/WebView;|Landroid/webkit/WebSettings;|"
            r"setJavaScriptEnabled|addJavascriptInterface|setAllowFileAccess)"
        ),
        "dynamic_loading": re.compile(r"(DexClassLoader|PathClassLoader|loadClass|loadLibrary|System;->load)"),
        "reflection": re.compile(
            r"(Ljava/lang/reflect/|Ljava/lang/Class;->forName|->getMethod|"
            r"->getDeclaredMethod)"
        ),
        "crypto": re.compile(
            r"(Ljavax/crypto/|Ljava/security/MessageDigest;|"
            r"Ljava/security/SecureRandom;|Cipher;->getInstance)"
        ),
        "trust_manager": re.compile(r"(Ljavax/net/ssl/|X509TrustManager|HostnameVerifier|TrustManager)"),
        "runtime_exec": re.compile(r"(Ljava/lang/Runtime;->exec|ProcessBuilder)"),
    }
    ENDPOINT_PATTERNS = {
        "url": re.compile(r"https?://[^\s\"'<>]+", re.IGNORECASE),
        "domain": re.compile(
            r"\b[a-z0-9][a-z0-9.-]*\."
            r"(?:com|net|org|io|dev|app|co|gov|edu|cloud|info|biz)\b",
            re.IGNORECASE,
        ),
        "ip_address": re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"),
        "jwt": re.compile(r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b"),
        "secret_keyword": re.compile(r"(?i)(api[_-]?key|client[_-]?secret|secret[_-]?key|access[_-]?token)"),
    }
    SECURITY_RELEVANT_ASSET_SUFFIXES = {
        ".cer",
        ".crt",
        ".db",
        ".der",
        ".html",
        ".js",
        ".json",
        ".pem",
        ".properties",
        ".sqlite",
        ".txt",
        ".xml",
    }

    @property
    def scan_type(self) -> ScanType:
        return ScanType.APKTOOL

    @property
    def name(self) -> str:
        return "Apktool Evidence Extractor"

    @property
    def description(self) -> str:
        return "Normalized Android security evidence reconstructed from an APK."

    def is_available(self) -> bool:
        return shutil.which("apktool") is not None

    def scan(self, config: ScanConfig) -> list[ScanResult]:
        apk_path = self._resolve_apk_path(config.project_path)
        if apk_path is None:
            return [
                ScanResult(
                    scanner_name=self.name,
                    scan_type=self.scan_type,
                    success=False,
                    skipped=True,
                    error_message="Apktool only runs on APK files.",
                )
            ]

        apktool_executable = shutil.which("apktool")
        if not apktool_executable:
            return [
                ScanResult(
                    scanner_name=self.name,
                    scan_type=self.scan_type,
                    success=False,
                    skipped=True,
                    error_message="The 'apktool' command is not installed on this system.",
                )
            ]

        temp_dir = Path(tempfile.mkdtemp(prefix="phoenix_apktool_"))
        errors: list[dict[str, Any]] = []
        try:
            decode_result = self._decode_apk(apktool_executable, apk_path, temp_dir)
            artifacts = self._extract_artifacts(decode_result, errors)
            artifacts["decode_metadata.json"] = self._decode_metadata(apk_path, decode_result, artifacts, errors)
            artifacts["extraction_errors.json"] = {"errors": errors}
            artifacts["evidence_index.json"] = self._evidence_index(artifacts)
            return self._scan_results(artifacts, decode_result, errors)
        except Exception as exc:
            return [
                ScanResult(
                    scanner_name=self.name,
                    scan_type=self.scan_type,
                    success=False,
                    error_message=str(exc),
                )
            ]
        finally:
            shutil.rmtree(temp_dir, ignore_errors=True)

    def _resolve_apk_path(self, project_path: Path) -> Path | None:
        if project_path.is_file():
            return project_path if is_apk_file(project_path) else None
        return find_apk_in_directory(project_path)

    def _decode_apk(
        self,
        apktool_executable: str,
        apk_path: Path,
        temp_dir: Path,
    ) -> ApktoolDecodeResult:
        decoded_root = temp_dir / "decoded"
        result = subprocess.run(
            [
                apktool_executable,
                "d",
                "-f",
                "-o",
                str(decoded_root),
                str(apk_path),
            ],
            capture_output=True,
            text=True,
            check=False,
            timeout=self.DEFAULT_TIMEOUT_SECONDS,
        )
        return ApktoolDecodeResult(
            decoded_root=decoded_root,
            exit_code=result.returncode,
            stdout=result.stdout,
            stderr=result.stderr,
            apktool_version=self._apktool_version(apktool_executable),
        )

    def _apktool_version(self, apktool_executable: str) -> str:
        try:
            result = subprocess.run(
                [apktool_executable, "--version"],
                capture_output=True,
                text=True,
                check=False,
                timeout=10,
            )
        except Exception:
            return ""
        return result.stdout.strip() or result.stderr.strip()

    def _extract_artifacts(
        self,
        decode_result: ApktoolDecodeResult,
        errors: list[dict[str, Any]],
    ) -> dict[str, Any]:
        extractors = [
            ("manifest_summary.json", self._extract_manifest_summary),
            ("permissions.json", self._extract_permissions),
            ("attack_surface.json", self._extract_attack_surface),
            ("deep_links.json", self._extract_deep_links),
            ("network_security_config.json", self._extract_network_security_config),
            ("trust_boundaries.json", self._extract_trust_boundaries),
            ("code_indicators.json", self._extract_code_indicators),
            ("secrets_endpoints.json", self._extract_secrets_endpoints),
            ("native_libraries.json", self._extract_native_libraries),
            ("assets_inventory.json", self._extract_assets_inventory),
        ]
        artifacts: dict[str, Any] = {}
        for artifact_name, extractor in extractors:
            try:
                artifacts[artifact_name] = extractor(decode_result.decoded_root)
            except Exception as exc:
                errors.append({"artifact": artifact_name, "error": str(exc)})
                artifacts[artifact_name] = {"items": [], "partial_failure": True}
        return artifacts

    def _extract_manifest_summary(self, decoded_root: Path) -> dict[str, Any]:
        manifest = self._load_manifest(decoded_root)
        root = manifest.getroot()
        application = root.find("application")
        apktool_metadata = self._apktool_yml_metadata(decoded_root)
        return {
            "package": root.attrib.get("package", ""),
            "min_sdk": apktool_metadata.get("min_sdk", ""),
            "target_sdk": apktool_metadata.get("target_sdk", ""),
            "version_code": self._android_attr(root, "versionCode") or apktool_metadata.get("version_code", ""),
            "version_name": self._android_attr(root, "versionName") or apktool_metadata.get("version_name", ""),
            "application": {
                "debuggable": self._android_attr(application, "debuggable"),
                "allow_backup": self._android_attr(application, "allowBackup"),
                "uses_cleartext_traffic": self._android_attr(application, "usesCleartextTraffic"),
                "network_security_config": self._android_attr(application, "networkSecurityConfig"),
            },
            "provenance": self._provenance(decoded_root, decoded_root / "AndroidManifest.xml"),
        }

    def _extract_permissions(self, decoded_root: Path) -> dict[str, Any]:
        manifest = self._load_manifest(decoded_root)
        root = manifest.getroot()
        requested = []
        declared = []
        for item in self._children_with_local_name(root, "uses-permission"):
            requested.append(
                self._evidence(
                    "requested_permission",
                    self._android_attr(item, "name"),
                    decoded_root,
                    decoded_root / "AndroidManifest.xml",
                    {"max_sdk_version": self._android_attr(item, "maxSdkVersion")},
                )
            )
        for item in self._children_with_local_name(root, "permission"):
            declared.append(
                self._evidence(
                    "declared_permission",
                    self._android_attr(item, "name"),
                    decoded_root,
                    decoded_root / "AndroidManifest.xml",
                    {"protection_level": self._android_attr(item, "protectionLevel")},
                )
            )
        return {"requested": requested, "declared": declared}

    def _extract_attack_surface(self, decoded_root: Path) -> dict[str, Any]:
        manifest = self._load_manifest(decoded_root)
        components = []
        for component_type in ("activity", "service", "receiver", "provider"):
            for element in manifest.findall(f".//{component_type}"):
                intent_filters = self._intent_filters(element)
                context = {
                    "component_type": component_type,
                    "exported": self._component_exported(element, intent_filters),
                    "permission": self._android_attr(element, "permission"),
                    "intent_filters": intent_filters,
                }
                if component_type == "provider":
                    context["authorities"] = self._android_attr(element, "authorities")
                components.append(
                    self._evidence(
                        "android_component",
                        self._android_attr(element, "name"),
                        decoded_root,
                        decoded_root / "AndroidManifest.xml",
                        context,
                    )
                )
        return {"components": sorted(components, key=lambda item: item["value"])}

    def _extract_deep_links(self, decoded_root: Path) -> dict[str, Any]:
        manifest = self._load_manifest(decoded_root)
        links = []
        for activity in manifest.findall(".//activity"):
            activity_name = self._android_attr(activity, "name")
            for intent_filter in activity.findall("intent-filter"):
                actions = [self._android_attr(action, "name") for action in intent_filter.findall("action")]
                categories = [self._android_attr(category, "name") for category in intent_filter.findall("category")]
                for data in intent_filter.findall("data"):
                    context = {
                        "activity": activity_name,
                        "actions": actions,
                        "categories": categories,
                        "scheme": self._android_attr(data, "scheme"),
                        "host": self._android_attr(data, "host"),
                        "port": self._android_attr(data, "port"),
                        "path": self._android_attr(data, "path"),
                        "path_prefix": self._android_attr(data, "pathPrefix"),
                        "path_pattern": self._android_attr(data, "pathPattern"),
                        "auto_verify": self._android_attr(intent_filter, "autoVerify"),
                    }
                    value = "://".join(part for part in (context["scheme"], context["host"]) if part)
                    links.append(
                        self._evidence(
                            "deep_link",
                            value,
                            decoded_root,
                            decoded_root / "AndroidManifest.xml",
                            context,
                        )
                    )
        return {"deep_links": sorted(links, key=lambda item: json.dumps(item, sort_keys=True))}

    def _extract_network_security_config(self, decoded_root: Path) -> dict[str, Any]:
        manifest_summary = self._extract_manifest_summary(decoded_root)
        reference = manifest_summary["application"]["network_security_config"]
        config_path = self._resource_reference_path(decoded_root, reference)
        if config_path is None or not config_path.exists():
            return {
                "reference": reference,
                "config_file_present": False,
                "manifest_uses_cleartext_traffic": manifest_summary["application"]["uses_cleartext_traffic"],
                "target_sdk": manifest_summary["target_sdk"],
                "effective_cleartext_traffic_default": self._cleartext_default(manifest_summary),
                "policy_source": "manifest_default_no_network_security_config",
                "domains": [],
                "debug_overrides": [],
                "provenance": self._provenance(decoded_root, decoded_root / "AndroidManifest.xml"),
            }

        tree = ElementTree.parse(config_path)
        root = tree.getroot()
        domains = []
        for domain_config in root.findall(".//domain-config"):
            domains.append(
                {
                    "cleartext_permitted": domain_config.attrib.get("cleartextTrafficPermitted", ""),
                    "domains": [
                        {
                            "value": (domain.text or "").strip(),
                            "include_subdomains": domain.attrib.get("includeSubdomains", ""),
                        }
                        for domain in domain_config.findall("domain")
                    ],
                    "trust_anchors": self._trust_anchor_sources(domain_config),
                    "pin_sets": len(domain_config.findall(".//pin-set")),
                    "provenance": self._provenance(decoded_root, config_path),
                }
            )
        return {
            "reference": reference,
            "config_file_present": True,
            "manifest_uses_cleartext_traffic": manifest_summary["application"]["uses_cleartext_traffic"],
            "target_sdk": manifest_summary["target_sdk"],
            "effective_cleartext_traffic_default": self._cleartext_default(manifest_summary),
            "policy_source": "network_security_config",
            "domains": domains,
            "debug_overrides": [
                {
                    "trust_anchors": self._trust_anchor_sources(debug_overrides),
                    "provenance": self._provenance(decoded_root, config_path),
                }
                for debug_overrides in root.findall(".//debug-overrides")
            ],
        }

    def _extract_trust_boundaries(self, decoded_root: Path) -> dict[str, Any]:
        attack_surface = self._extract_attack_surface(decoded_root)["components"]
        boundaries = []
        for component in attack_surface:
            context = component["context"]
            if context.get("exported") == "true":
                boundaries.append(
                    {
                        "evidence_type": "exported_component_boundary",
                        "value": component["value"],
                        "context": context,
                        "provenance": component["provenance"],
                    }
                )
        return {"items": sorted(boundaries, key=lambda item: item["value"])}

    def _extract_code_indicators(self, decoded_root: Path) -> dict[str, Any]:
        return {"items": self._scan_text_patterns(decoded_root, self.CODE_PATTERNS, "code_indicator")}

    def _extract_secrets_endpoints(self, decoded_root: Path) -> dict[str, Any]:
        return {
            "items": self._scan_text_patterns(
                decoded_root,
                self.ENDPOINT_PATTERNS,
                "secret_or_endpoint",
                include_context=True,
            )
        }

    def _extract_native_libraries(self, decoded_root: Path) -> dict[str, Any]:
        libraries = []
        lib_root = decoded_root / "lib"
        if not lib_root.exists():
            return {"libraries": libraries}
        for path in sorted(lib_root.rglob("*.so")):
            if path.is_symlink() or not path.is_file():
                continue
            relative = path.relative_to(decoded_root)
            libraries.append(
                {
                    "name": path.name,
                    "abi": relative.parts[1] if len(relative.parts) > 2 else "",
                    "path": relative.as_posix(),
                    "size_bytes": path.stat().st_size,
                    "sha256": self._sha256(path),
                    "provenance": self._provenance(decoded_root, path),
                }
            )
        return {"libraries": libraries}

    def _extract_assets_inventory(self, decoded_root: Path) -> dict[str, Any]:
        assets = []
        for base in (decoded_root / "assets", decoded_root / "res" / "raw"):
            if not base.exists():
                continue
            for path in sorted(base.rglob("*")):
                if path.is_symlink() or not path.is_file():
                    continue
                if path.suffix.lower() not in self.SECURITY_RELEVANT_ASSET_SUFFIXES:
                    continue
                assets.append(
                    {
                        "name": path.name,
                        "path": path.relative_to(decoded_root).as_posix(),
                        "suffix": path.suffix.lower(),
                        "size_bytes": path.stat().st_size,
                        "sha256": self._sha256(path),
                        "provenance": self._provenance(decoded_root, path),
                    }
                )
        return {"assets": assets}

    def _scan_text_patterns(
        self,
        decoded_root: Path,
        patterns: dict[str, re.Pattern[str]],
        evidence_type: str,
        *,
        include_context: bool = False,
    ) -> list[dict[str, Any]]:
        counts = {category: 0 for category in patterns}
        items = []
        for path in self._iter_text_files(decoded_root):
            text = path.read_text(encoding="utf-8", errors="ignore")
            for line_number, line in enumerate(text.splitlines(), start=1):
                for category, pattern in patterns.items():
                    if counts[category] >= self.MAX_MATCHES_PER_CATEGORY:
                        continue
                    for match in pattern.finditer(line):
                        counts[category] += 1
                        context = {"category": category}
                        if include_context:
                            context["line_context"] = self._short_context(line, match)
                        items.append(
                            self._evidence(
                                evidence_type,
                                match.group(0),
                                decoded_root,
                                path,
                                context,
                                line_number=line_number,
                            )
                        )
                        if counts[category] >= self.MAX_MATCHES_PER_CATEGORY:
                            break
        return sorted(items, key=lambda item: json.dumps(item, sort_keys=True))

    def _iter_text_files(self, decoded_root: Path) -> list[Path]:
        candidates = []
        for path in sorted(decoded_root.rglob("*")):
            if len(candidates) >= self.MAX_SMALI_FILES:
                break
            if path.is_symlink() or not path.is_file():
                continue
            if path.stat().st_size > self.MAX_TEXT_FILE_BYTES:
                continue
            if path.suffix.lower() in {
                ".smali",
                ".xml",
                ".json",
                ".txt",
                ".properties",
            }:
                candidates.append(path)
        return candidates

    def _load_manifest(self, decoded_root: Path) -> ElementTree.ElementTree:
        return ElementTree.parse(decoded_root / "AndroidManifest.xml")

    def _android_attr(self, element: ElementTree.Element | None, name: str) -> str:
        if element is None:
            return ""
        return element.attrib.get(f"{ANDROID_NS}{name}", element.attrib.get(name, ""))

    def _children_with_local_name(
        self,
        element: ElementTree.Element,
        local_name: str,
    ) -> list[ElementTree.Element]:
        return [child for child in element if self._local_name(child.tag) == local_name]

    def _local_name(self, tag: str) -> str:
        if "}" in tag:
            return tag.rsplit("}", 1)[1]
        if ":" in tag:
            return tag.rsplit(":", 1)[1]
        return tag

    def _apktool_yml_metadata(self, decoded_root: Path) -> dict[str, str]:
        metadata = {
            "min_sdk": "",
            "target_sdk": "",
            "version_code": "",
            "version_name": "",
        }
        path = decoded_root / "apktool.yml"
        if not path.exists():
            return metadata

        section = ""
        for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
            stripped = line.strip()
            if not stripped:
                continue
            if not line.startswith(" ") and stripped.endswith(":"):
                section = stripped.removesuffix(":")
                continue
            if ":" not in stripped:
                continue
            key, value = stripped.split(":", 1)
            value = value.strip().strip("'\"")
            if section == "sdkInfo" and key == "minSdkVersion":
                metadata["min_sdk"] = value
            elif section == "sdkInfo" and key == "targetSdkVersion":
                metadata["target_sdk"] = value
            elif section == "versionInfo" and key == "versionCode":
                metadata["version_code"] = value
            elif section == "versionInfo" and key == "versionName":
                metadata["version_name"] = value
        return metadata

    def _cleartext_default(self, manifest_summary: dict[str, Any]) -> str:
        explicit = manifest_summary["application"]["uses_cleartext_traffic"]
        if explicit:
            return explicit
        try:
            target_sdk = int(manifest_summary["target_sdk"])
        except (TypeError, ValueError):
            return "unknown"
        return "false" if target_sdk >= 28 else "true"

    def _intent_filters(self, element: ElementTree.Element) -> list[dict[str, Any]]:
        filters = []
        for intent_filter in element.findall("intent-filter"):
            filters.append(
                {
                    "actions": [self._android_attr(action, "name") for action in intent_filter.findall("action")],
                    "categories": [
                        self._android_attr(category, "name") for category in intent_filter.findall("category")
                    ],
                    "data": [
                        {
                            "scheme": self._android_attr(data, "scheme"),
                            "host": self._android_attr(data, "host"),
                            "path": self._android_attr(data, "path"),
                            "path_prefix": self._android_attr(data, "pathPrefix"),
                            "path_pattern": self._android_attr(data, "pathPattern"),
                        }
                        for data in intent_filter.findall("data")
                    ],
                }
            )
        return filters

    def _component_exported(
        self,
        element: ElementTree.Element,
        intent_filters: list[dict[str, Any]],
    ) -> str:
        exported = self._android_attr(element, "exported")
        if exported:
            return exported
        return "true" if intent_filters else "false"

    def _resource_reference_path(self, decoded_root: Path, reference: str) -> Path | None:
        if not reference.startswith("@xml/"):
            return None
        name = reference.removeprefix("@xml/")
        return decoded_root / "res" / "xml" / f"{name}.xml"

    def _trust_anchor_sources(self, element: ElementTree.Element) -> list[str]:
        sources = []
        for certificates in element.findall(".//certificates"):
            source = certificates.attrib.get("src", "")
            if source:
                sources.append(source)
        return sorted(set(sources))

    def _decode_metadata(
        self,
        apk_path: Path,
        decode_result: ApktoolDecodeResult,
        artifacts: dict[str, Any],
        errors: list[dict[str, Any]],
    ) -> dict[str, Any]:
        decoded_files_used = sorted(
            self._artifact_sources(artifact) for artifact in artifacts.values() if isinstance(artifact, dict)
        )
        decoded_files_used = sorted({source for sources in decoded_files_used for source in sources})
        partial_success = decode_result.exit_code != 0 and bool(decoded_files_used)
        return {
            "tool": "apktool",
            "tool_available": True,
            "apktool_version": decode_result.apktool_version,
            "apk_name": apk_path.name,
            "apk_sha256": self._sha256(apk_path),
            "decode_exit_code": decode_result.exit_code,
            "partial_success": partial_success,
            "decoded_files_used": decoded_files_used,
            "stderr_summary": self._summarize_lines(decode_result.stderr),
            "stdout_summary": self._summarize_lines(decode_result.stdout),
            "extraction_error_count": len(errors),
        }

    def _artifact_sources(self, value: Any) -> list[str]:
        sources = []
        if isinstance(value, dict):
            provenance = value.get("provenance")
            if isinstance(provenance, dict) and provenance.get("path"):
                sources.append(str(provenance["path"]))
            for item in value.values():
                sources.extend(self._artifact_sources(item))
        elif isinstance(value, list):
            for item in value:
                sources.extend(self._artifact_sources(item))
        return sources

    def _evidence_index(self, artifacts: dict[str, Any]) -> dict[str, Any]:
        return {
            "artifacts": [
                {
                    "name": name,
                    "item_count": self._count_items(value),
                }
                for name, value in sorted(artifacts.items())
            ]
        }

    def _count_items(self, value: Any) -> int:
        if isinstance(value, dict):
            if isinstance(value.get("items"), list):
                return len(value["items"])
            return sum(self._count_items(item) for item in value.values())
        if isinstance(value, list):
            return len(value)
        return 0

    def _scan_results(
        self,
        artifacts: dict[str, Any],
        decode_result: ApktoolDecodeResult,
        errors: list[dict[str, Any]],
    ) -> list[ScanResult]:
        extracted_any = any(
            name not in {"decode_metadata.json", "extraction_errors.json"} and self._count_items(value) > 0
            for name, value in artifacts.items()
        )
        overall_success = decode_result.exit_code == 0 or extracted_any
        return [
            ScanResult(
                scanner_name=self.name,
                scan_type=self.scan_type,
                success=overall_success,
                error_message="" if overall_success else self._first_error(decode_result, errors),
                raw_output=json.dumps(value, indent=2, sort_keys=True),
                relative_target_path=artifact_name,
                description=self.description,
            )
            for artifact_name, value in sorted(artifacts.items())
        ]

    def _first_error(
        self,
        decode_result: ApktoolDecodeResult,
        errors: list[dict[str, Any]],
    ) -> str:
        if decode_result.stderr.strip():
            return decode_result.stderr.strip().splitlines()[0]
        if errors:
            return str(errors[0].get("error", "Apktool evidence extraction failed."))
        return "Apktool evidence extraction failed."

    def _evidence(
        self,
        evidence_type: str,
        value: str,
        decoded_root: Path,
        path: Path,
        context: dict[str, Any] | None = None,
        *,
        line_number: int | None = None,
    ) -> dict[str, Any]:
        return {
            "evidence_type": evidence_type,
            "value": value,
            "context": context or {},
            "provenance": self._provenance(decoded_root, path, line_number=line_number),
        }

    def _provenance(
        self,
        decoded_root: Path,
        path: Path,
        *,
        line_number: int | None = None,
    ) -> dict[str, Any]:
        try:
            relative_path = path.relative_to(decoded_root).as_posix()
        except ValueError:
            relative_path = path.name
        return {
            "source": path.name,
            "path": relative_path,
            "line": line_number,
            "apktool_artifact": "decoded_apk",
            "extraction_method": "apktool_normalized_evidence",
        }

    def _short_context(self, line: str, match: re.Match[str]) -> str:
        start = max(0, match.start() - self.SECRET_CONTEXT_CHARS)
        end = min(len(line), match.end() + self.SECRET_CONTEXT_CHARS)
        return line[start:end].strip()

    def _summarize_lines(self, text: str) -> list[str]:
        return [line.strip() for line in text.splitlines() if line.strip()][:20]

    def _sha256(self, path: Path) -> str:
        digest = hashlib.sha256()
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
        return digest.hexdigest()
